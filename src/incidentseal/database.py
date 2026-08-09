"""Host-owned real migration and PostgreSQL surface probe."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .runtime import _build_images, _compose_args, _compose_env, _inspect_container, _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wait_healthy(docker: str, container: str, *, seconds: int = 90) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        health = json.loads(_run(docker, ["inspect", container, "--format", "{{json .State.Health.Status}}"]).stdout)
        if health == "healthy":
            return
        time.sleep(1)
    logs = subprocess.run(
        [docker, "logs", container],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    combined = (logs.stdout + logs.stderr).strip()
    tail = combined.splitlines()[-1][:350] if combined else "no database logs were available"
    raise TopologyError("IS_DATABASE_HEALTH", f"PostgreSQL did not become healthy: {tail}")


def _psql_arguments(user: str, sql: str) -> list[str]:
    return [
        "--host=database",
        f"--username={user}",
        "--dbname=incidentseal",
        "--set=ON_ERROR_STOP=1",
        "--tuples-only",
        "--no-align",
        f"--command={sql}",
    ]


def _run_psql(
    docker: str,
    base: list[str],
    env: dict[str, str],
    name: str,
    user: str,
    sql: str,
    created_names: list[str],
) -> subprocess.CompletedProcess[str]:
    created_names.append(name)
    return _run(
        docker,
        [*base, "run", "--name", name, "--no-deps", "migration", *_psql_arguments(user, sql)],
        env=env,
    )


def _run_psql_expected_failure(
    docker: str,
    base: list[str],
    env: dict[str, str],
    name: str,
    user: str,
    sql: str,
    created_names: list[str],
) -> subprocess.CompletedProcess[str]:
    created_names.append(name)
    return subprocess.run(
        [docker, *base, "run", "--name", name, "--no-deps", "migration", *_psql_arguments(user, sql)],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=180,
        check=False,
    )


def _last_json(result: subprocess.CompletedProcess[str]) -> Any:
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise TopologyError("IS_DATABASE_QUERY", "PostgreSQL query returned no machine value")
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise TopologyError("IS_DATABASE_QUERY", "PostgreSQL query did not return JSON") from error


def _check(checks: list[dict[str, Any]], check_id: str, passed: bool, observed: Any) -> None:
    checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})


def database_probe() -> dict[str, Any]:
    static = validate_platform_topology()
    docker = _docker_executable()
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    services = {item["id"]: item for item in contract["services"]}
    admin_user = services["database"]["environment"]["POSTGRES_USER"]
    python_user = services["python-runner"]["environment"]["PGUSER"]
    node_user = services["node-runner"]["environment"]["PGUSER"]
    if python_user != node_user:
        raise TopologyError("IS_DATABASE_CONTRACT", "runner database roles differ")
    runner_user = python_user

    with tempfile.TemporaryDirectory(prefix="incidentseal-database-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        (custody / "input" / "request.json").write_text("{}\n", encoding="utf-8")
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, project, run_id = _compose_env(contract, identities, custody)
        base = _compose_args(env_file)
        network = f"{project}_data"
        database_name = f"{project}-database-1"
        volume = f"{project}_database-data"
        migration_names = [f"{project}-migration-real", f"{project}-migration-idempotent"]
        created_names: list[str] = []
        checks: list[dict[str, Any]] = []
        inspections: list[dict[str, Any]] = []
        query_evidence: dict[str, Any] = {}

        if _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip():
            raise TopologyError("IS_DATABASE_STALE", "pre-existing database probe container conflicts with the run")
        if _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip():
            raise TopologyError("IS_DATABASE_STALE", "pre-existing database probe network conflicts with the run")
        existing_volume = _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip()
        if not existing_volume:
            raise TopologyError("IS_DATABASE_STALE", "the exact topology-security volume is unavailable")
        volume_inspect = json.loads(_run(docker, ["volume", "inspect", volume]).stdout)[0]
        labels = volume_inspect.get("Labels") or {}
        if labels.get("dev.incidentseal.contract-digest") != _sha256_file(CONTRACT_PATH) or labels.get("dev.incidentseal.manifest-digest") != "not-used":
            raise TopologyError("IS_DATABASE_STALE", "the retained volume is not bound to the active topology")

        try:
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database_name)
            inspections.append(_inspect_container(docker, database_name, identities["database"], "70:70", network))
            _check(checks, "database-health", True, "healthy")

            for index, name in enumerate(migration_names):
                created_names.append(name)
                result = _run(docker, [*base, "run", "--name", name, "--no-deps", "migration"], env=env)
                inspections.append(_inspect_container(docker, name, identities["migration"], "70:70", network))
                query_evidence[f"migration_{index + 1}_output_digest"] = _digest(result.stdout)
            _check(checks, "migration-idempotency", True, query_evidence)

            identity_sql = """SELECT json_build_object(
              'server_version_num', current_setting('server_version_num')::integer,
              'database', current_database(),
              'current_user', current_user,
              'session_user', session_user,
              'superuser', r.rolsuper,
              'create_database', r.rolcreatedb,
              'create_role', r.rolcreaterole
            )::text FROM pg_roles r WHERE r.rolname = current_user;"""
            identity = _last_json(
                _run_psql(docker, base, env, f"{project}-query-identity", admin_user, identity_sql, created_names)
            )
            query_evidence["database_identity"] = identity
            identity_ok = all(
                [
                    identity.get("database") == "incidentseal",
                    identity.get("current_user") == admin_user,
                    identity.get("session_user") == admin_user,
                    identity.get("superuser") is True,
                    180000 <= int(identity.get("server_version_num", 0)) < 190000,
                ]
            )
            _check(checks, "database-identity", identity_ok, identity)

            role_sql = f"""SELECT json_build_object(
              'role', rolname,
              'can_login', rolcanlogin,
              'superuser', rolsuper,
              'create_database', rolcreatedb,
              'create_role', rolcreaterole,
              'replication', rolreplication,
              'bypass_rls', rolbypassrls
            )::text FROM pg_roles WHERE rolname = '{runner_user}';"""
            role = _last_json(
                _run_psql(docker, base, env, f"{project}-query-role", admin_user, role_sql, created_names)
            )
            query_evidence["runner_role"] = role
            least_privilege = all(
                [
                    runner_user != admin_user,
                    role.get("role") == runner_user,
                    role.get("can_login") is True,
                    role.get("superuser") is False,
                    role.get("create_database") is False,
                    role.get("create_role") is False,
                    role.get("replication") is False,
                    role.get("bypass_rls") is False,
                ]
            )
            _check(checks, "runner-role-least-privilege", least_privilege, role)

            schema_sql = """SELECT json_build_object(
              'table_exists', to_regclass('public.verification_results') IS NOT NULL,
              'columns', COALESCE((
                SELECT json_agg(json_build_object('name', column_name, 'type', data_type, 'nullable', is_nullable = 'YES') ORDER BY ordinal_position)
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'verification_results'
              ), '[]'::json),
              'primary_key', COALESCE((
                SELECT json_agg(a.attname ORDER BY k.ordinality)
                FROM pg_index i
                JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality) ON true
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                WHERE i.indrelid = 'public.verification_results'::regclass AND i.indisprimary
              ), '[]'::json)
            )::text;"""
            schema = _last_json(
                _run_psql(docker, base, env, f"{project}-query-schema", admin_user, schema_sql, created_names)
            )
            query_evidence["schema"] = schema
            expected_columns = [
                {"name": "run_id", "type": "text", "nullable": False},
                {"name": "runner", "type": "text", "nullable": False},
                {"name": "input_digest", "type": "text", "nullable": False},
                {"name": "result_digest", "type": "text", "nullable": False},
            ]
            schema_ok = schema.get("table_exists") is True and schema.get("columns") == expected_columns and schema.get("primary_key") == ["run_id", "runner"]
            _check(checks, "schema-shape", schema_ok, schema)

            marker_input = _digest("incidentseal-u05-persistence-input")
            marker_result = _digest("incidentseal-u05-persistence-result")
            dml_sql = f"""INSERT INTO public.verification_results(run_id, runner, input_digest, result_digest)
              VALUES ('is3-u05-persistence', 'python', '{marker_input}', '{marker_result}')
              ON CONFLICT (run_id, runner) DO UPDATE SET input_digest = EXCLUDED.input_digest, result_digest = EXCLUDED.result_digest;
              SELECT json_build_object('row_count', count(*), 'result_digest', max(result_digest))::text
              FROM public.verification_results WHERE run_id = 'is3-u05-persistence' AND runner = 'python';"""
            dml = _last_json(
                _run_psql(docker, base, env, f"{project}-query-runner-dml", runner_user, dml_sql, created_names)
            )
            query_evidence["runner_dml"] = dml
            _check(checks, "runner-bounded-dml", dml == {"row_count": 1, "result_digest": marker_result}, dml)

            ddl_name = f"{project}-query-runner-ddl"
            ddl = _run_psql_expected_failure(
                docker,
                base,
                env,
                ddl_name,
                runner_user,
                "CREATE TABLE public.incidentseal_forbidden_probe (id integer);",
                created_names,
            )
            ddl_text = (ddl.stdout + ddl.stderr).strip()
            ddl_denied = ddl.returncode != 0 and "permission denied" in ddl_text.lower()
            query_evidence["runner_ddl_exit_code"] = ddl.returncode
            query_evidence["runner_ddl_output_digest"] = _digest(ddl_text)
            _check(checks, "runner-ddl-denied", ddl_denied, {"exit_code": ddl.returncode, "output_digest": _digest(ddl_text)})
            _run_psql(
                docker,
                base,
                env,
                f"{project}-query-ddl-cleanup",
                admin_user,
                "DROP TABLE IF EXISTS public.incidentseal_forbidden_probe;",
                created_names,
            )

            _run(docker, [*base, "stop", "database"], env=env)
            _run(docker, [*base, "start", "database"], env=env)
            _wait_healthy(docker, database_name)
            inspections.append(_inspect_container(docker, database_name, identities["database"], "70:70", network))
            persistence_sql = """SELECT json_build_object('row_count', count(*), 'result_digest', max(result_digest))::text
              FROM public.verification_results WHERE run_id = 'is3-u05-persistence' AND runner = 'python';"""
            persistence = _last_json(
                _run_psql(docker, base, env, f"{project}-query-persistence", admin_user, persistence_sql, created_names)
            )
            query_evidence["persistence"] = persistence
            _check(checks, "restart-persistence", persistence == {"row_count": 1, "result_digest": marker_result}, persistence)
        finally:
            for name in [*migration_names, *created_names]:
                subprocess.run([docker, "rm", "-f", name], cwd=ROOT, capture_output=True, check=False)
            subprocess.run([docker, *base, "down", "--remove-orphans"], cwd=ROOT, env=env, capture_output=True, check=False)

        containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        volume_left = _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip()
        teardown_ok = not containers_left and not network_left and volume_left == volume
        _check(checks, "teardown", teardown_ok, {"containers": containers_left, "network": network_left, "volume": volume_left})
        if not teardown_ok:
            raise TopologyError("IS_DATABASE_TEARDOWN", "database probe teardown or retained volume differs from the contract")
        verdict = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
        return {
            "schema_version": "incidentseal-database-probe/v1",
            "verdict": verdict,
            "mode": "platform-validation",
            "claim_scope": "database-migration-persistence-only",
            "project_name": project,
            "run_id": run_id,
            "contract_digest": _sha256_file(CONTRACT_PATH),
            "admin_user": admin_user,
            "runner_user": runner_user,
            "images": image_receipts,
            "checks": checks,
            "inspections": inspections,
            "query_evidence": query_evidence,
            "retained_volume": volume,
            "containers_removed": True,
            "network_removed": True,
            "runtime_started": True,
            "static_validation": static.data,
        }
