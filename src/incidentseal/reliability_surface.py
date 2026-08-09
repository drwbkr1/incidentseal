"""Host-owned disposable topology reliability probe."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .database import _last_json, _psql_arguments, _run_psql, _wait_healthy
from .node_surface import (
    _container_isolation as _node_isolation,
    _expected_result,
    _raw_compose,
    _remove_completed,
    _sha,
)
from .python_surface import _container_isolation as _python_isolation
from .runtime import _build_images, _compose_args, _compose_env, _inspect_container, _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


RETAINED_VOLUMES_LOCK = ROOT / "requirements" / "retained-runtime-volumes.lock.json"
VALID_FIXTURE = ROOT / "fixtures" / "topology" / "runner-request.valid.json"
INVALID_FIXTURE = ROOT / "fixtures" / "topology" / "runner-request.invalid.extra.json"
RECOVERY_FIXTURE = ROOT / "fixtures" / "topology" / "runner-request.recovery.json"


def _check(checks: list[dict[str, Any]], check_id: str, passed: bool, observed: Any) -> None:
    checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})


def _receipt_verdict(actual: Any, expected: dict[str, Any]) -> str:
    return "PASS" if actual == expected else "FAIL"


def _volume_names(docker: str) -> set[str]:
    return {line for line in _run(docker, ["volume", "ls", "--format", "{{.Name}}"]).stdout.splitlines() if line}


def _load_retained_volume_lock(docker: str) -> tuple[dict[str, Any], set[str]]:
    lock = _load(RETAINED_VOLUMES_LOCK)
    if lock.get("schema_version") != "incidentseal-retained-runtime-volumes-lock/v1":
        raise TopologyError("IS_RELIABILITY_VOLUME_LOCK", "retained-volume lock schema is unsupported")
    policy = lock.get("policy", {})
    if policy != {
        "delete": False,
        "rename": False,
        "relabel": False,
        "mount_in_disposable_reliability_project": False,
        "required_before_and_after_each_attempt": True,
    }:
        raise TopologyError("IS_RELIABILITY_VOLUME_LOCK", "retained-volume policy differs from the closed boundary")
    protected: set[str] = set()
    for item in lock.get("volumes", []):
        name = item.get("name")
        evidence = item.get("evidence", {})
        path = ROOT / str(evidence.get("path", ""))
        if not isinstance(name, str) or not name.startswith("incidentseal-"):
            raise TopologyError("IS_RELIABILITY_VOLUME_LOCK", "retained-volume name is invalid")
        if not path.is_file() or _sha256_file(path) != evidence.get("sha256"):
            raise TopologyError("IS_RELIABILITY_VOLUME_LOCK", f"retained-volume evidence drifted for {name}")
        protected.add(name)
    disposable = lock.get("disposable_project", {})
    if (
        len(protected) != 3
        or disposable.get("volume") in protected
        or disposable.get("delete_after_verified_teardown") is not True
        or disposable.get("contains_only_fixed_non-sensitive_test_rows") is not True
    ):
        raise TopologyError("IS_RELIABILITY_VOLUME_LOCK", "retained and disposable volume custody overlaps or is incomplete")
    available = _volume_names(docker)
    if not protected.issubset(available):
        raise TopologyError("IS_RELIABILITY_VOLUME_MISSING", "one or more retained evidence volumes are unavailable")
    return lock, protected


def _read_result(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _run_application(
    *,
    docker: str,
    base: list[str],
    env: dict[str, str],
    service: str,
    name: str,
    output_path: Path,
    expected: dict[str, Any],
    image_id: str,
    network: str,
    custody: Path,
    isolation: Callable[[str, str, Path, str], dict[str, Any]],
    created_names: list[str],
    inspections: list[dict[str, Any]],
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None, dict[str, Any]]:
    completed = _raw_compose(docker, base, env, ["run", "--name", name, "--no-deps", service])
    created_names.append(name)
    inspections.append(_inspect_container(docker, name, image_id, "65532:65532", network))
    isolation_result = isolation(docker, name, custody, network)
    actual = _read_result(output_path)
    only_output = output_path.is_file() and set(output_path.parent.iterdir()) == {output_path}
    observed = {
        "exit_code": completed.returncode,
        "stdout_digest": _sha(completed.stdout.encode()),
        "stderr_digest": _sha(completed.stderr.encode()),
        "result": actual,
        "result_file_digest": _sha(output_path.read_bytes()) if output_path.is_file() else None,
        "isolation": isolation_result,
    }
    passed = completed.returncode == 0 and not completed.stderr.strip() and actual == expected and only_output
    observed["passed"] = passed
    return completed, actual, observed


def _query_rows(
    docker: str,
    base: list[str],
    env: dict[str, str],
    project: str,
    admin_user: str,
    created_names: list[str],
    name_suffix: str,
) -> list[dict[str, Any]]:
    sql = """SELECT COALESCE(json_agg(row_to_json(rows) ORDER BY run_id, runner), '[]'::json)::text
      FROM (SELECT run_id, runner, input_digest, result_digest
      FROM public.verification_results) AS rows;"""
    value = _last_json(
        _run_psql(docker, base, env, f"{project}-query-{name_suffix}", admin_user, sql, created_names)
    )
    if not isinstance(value, list):
        raise TopologyError("IS_RELIABILITY_DATABASE", "reliability database query did not return a row list")
    return value


def _wait_running(docker: str, name: str, *, seconds: int = 15) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        completed = subprocess.run(
            [docker, "inspect", name], cwd=ROOT, text=True, encoding="utf-8", capture_output=True, check=False
        )
        if completed.returncode == 0:
            value = json.loads(completed.stdout)[0]
            if value.get("State", {}).get("Running") is True:
                return value
        time.sleep(0.2)
    raise TopologyError("IS_RELIABILITY_CANCELLATION", "cancellation target did not reach running state")


def reliability_probe() -> dict[str, Any]:
    static = validate_platform_topology()
    docker = _docker_executable()
    volume_lock, protected = _load_retained_volume_lock(docker)
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    services = {item["id"]: item for item in contract["services"]}
    admin_user = services["database"]["environment"]["POSTGRES_USER"]
    disposable = volume_lock["disposable_project"]
    project = disposable["name"]
    volume = disposable["volume"]
    network = f"{project}_data"
    database_name = f"{project}-database-1"

    with tempfile.TemporaryDirectory(prefix="incidentseal-reliability-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        if ROOT in custody.parents or custody == ROOT or any(part.casefold() == "onedrive" for part in custody.parts):
            raise TopologyError("IS_RELIABILITY_CUSTODY", "reliability custody overlaps a forbidden root")
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        request_path = custody / "input" / "request.json"
        python_output = custody / "python-output" / "result.json"
        node_output = custody / "node-output" / "result.json"
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, _, _ = _compose_env(contract, identities, custody)
        env["INCIDENTSEAL_PROJECT_NAME"] = project
        env["INCIDENTSEAL_RUN_ID"] = "isrun-2222222222222222"
        base = _compose_args(env_file)
        migration_name = f"{project}-migration-reliability"
        python_name = f"{project}-python-valid"
        node_name = f"{project}-node-valid"
        python_invalid_name = f"{project}-python-invalid"
        node_invalid_name = f"{project}-node-invalid"
        python_failed_name = f"{project}-python-database-failed"
        python_recovery_name = f"{project}-python-recovery"
        cancel_name = f"{project}-cancel-query"
        created_names: list[str] = []
        checks: list[dict[str, Any]] = []
        inspections: list[dict[str, Any]] = []
        evidence: dict[str, Any] = {}

        before_volumes = _volume_names(docker)
        stale_containers = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        stale_network = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        if stale_containers or stale_network or volume in before_volumes:
            raise TopologyError("IS_RELIABILITY_STALE", "disposable reliability resources already exist")

        cleanup_exit_code: int | None = None
        try:
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database_name)
            inspections.append(_inspect_container(docker, database_name, identities["database"], "70:70", network))
            created_names.append(migration_name)
            _run(docker, [*base, "run", "--name", migration_name, "--no-deps", "migration"], env=env)
            inspections.append(_inspect_container(docker, migration_name, identities["migration"], "70:70", network))
            _remove_completed(docker, created_names)
            fresh_ok = volume in _volume_names(docker)
            _check(checks, "fresh-bootstrap", fresh_ok, {"volume": volume, "database_healthy": True})

            valid_request = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))
            request_path.write_bytes(VALID_FIXTURE.read_bytes())
            expected_python = _expected_result(valid_request, "python")
            expected_node = _expected_result(valid_request, "node")
            _, actual_python, python_observed = _run_application(
                docker=docker, base=base, env=env, service="python-runner", name=python_name,
                output_path=python_output, expected=expected_python, image_id=identities["python-runner"],
                network=network, custody=custody, isolation=_python_isolation,
                created_names=created_names, inspections=inspections,
            )
            _check(checks, "fresh-python-runner", bool(python_observed["passed"]), python_observed)
            _remove_completed(docker, created_names)
            _, actual_node, node_observed = _run_application(
                docker=docker, base=base, env=env, service="node-runner", name=node_name,
                output_path=node_output, expected=expected_node, image_id=identities["node-runner"],
                network=network, custody=custody, isolation=_node_isolation,
                created_names=created_names, inspections=inspections,
            )
            _check(checks, "fresh-node-runner", bool(node_observed["passed"]), node_observed)
            rows = _query_rows(docker, base, env, project, admin_user, created_names, "fresh-rows")
            expected_rows = sorted(
                [{key: value[key] for key in ("run_id", "runner", "input_digest", "result_digest")} for value in (expected_python, expected_node)],
                key=lambda item: (item["run_id"], item["runner"]),
            )
            _check(checks, "fresh-database-rows", rows == expected_rows, rows)
            _remove_completed(docker, created_names)

            tampered = dict(actual_node or {})
            tampered["result_digest"] = "sha256:" + "0" * 64
            node_output.write_text(json.dumps(tampered, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
            forced_verdict = _receipt_verdict(_read_result(node_output), expected_node)
            _check(
                checks,
                "forced-verification-failure",
                forced_verdict == "FAIL",
                {"lifecycle":"completed","verification_verdict":forced_verdict,"tampered_file_digest":_sha(node_output.read_bytes())},
            )
            node_output.unlink()
            python_output.unlink()

            request_path.write_bytes(INVALID_FIXTURE.read_bytes())
            invalid_observed: dict[str, Any] = {"lifecycle":"completed","verification_verdict":"INVALID"}
            invalid_pass = True
            for service, name, output_path, image_role, isolation in (
                ("python-runner", python_invalid_name, python_output, "python-runner", _python_isolation),
                ("node-runner", node_invalid_name, node_output, "node-runner", _node_isolation),
            ):
                completed = _raw_compose(docker, base, env, ["run", "--name", name, "--no-deps", service])
                created_names.append(name)
                inspections.append(_inspect_container(docker, name, identities[image_role], "65532:65532", network))
                isolation(docker, name, custody, network)
                text = (completed.stdout + completed.stderr).strip()
                item_ok = completed.returncode != 0 and "request shape is invalid" in text and not output_path.exists()
                invalid_pass = invalid_pass and item_ok
                invalid_observed[service] = {"exit_code":completed.returncode,"output_digest":_sha(text.encode()),"output_exists":output_path.exists()}
                _remove_completed(docker, created_names)
            invalid_rows = _query_rows(docker, base, env, project, admin_user, created_names, "invalid-rows")
            invalid_pass = invalid_pass and invalid_rows == expected_rows
            invalid_observed["database_rows_unchanged"] = invalid_rows == expected_rows
            _check(checks, "invalid-input-distinct", invalid_pass, invalid_observed)
            _remove_completed(docker, created_names)

            request_path.write_bytes(RECOVERY_FIXTURE.read_bytes())
            _run(docker, ["stop", "--time", "1", database_name])
            failed = _raw_compose(
                docker, base, env, ["run", "--name", python_failed_name, "--no-deps", "python-runner"]
            )
            created_names.append(python_failed_name)
            inspections.append(_inspect_container(docker, python_failed_name, identities["python-runner"], "65532:65532", network))
            _python_isolation(docker, python_failed_name, custody, network)
            failed_text = (failed.stdout + failed.stderr).strip()
            failed_ok = failed.returncode != 0 and not python_output.exists()
            _check(
                checks,
                "execution-failure-distinct",
                failed_ok,
                {"lifecycle":"failed","verification_verdict":None,"exit_code":failed.returncode,"output_digest":_sha(failed_text.encode())},
            )
            _remove_completed(docker, created_names)
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database_name)

            recovery_request = json.loads(RECOVERY_FIXTURE.read_text(encoding="utf-8"))
            expected_recovery = _expected_result(recovery_request, "python")
            rows_after_failure = _query_rows(docker, base, env, project, admin_user, created_names, "after-failure")
            _check(checks, "failed-run-no-database-row", rows_after_failure == expected_rows, rows_after_failure)
            _remove_completed(docker, created_names)
            _, actual_recovery, recovery_observed = _run_application(
                docker=docker, base=base, env=env, service="python-runner", name=python_recovery_name,
                output_path=python_output, expected=expected_recovery, image_id=identities["python-runner"],
                network=network, custody=custody, isolation=_python_isolation,
                created_names=created_names, inspections=inspections,
            )
            _check(checks, "post-failure-recovery", bool(recovery_observed["passed"]), recovery_observed)
            _remove_completed(docker, created_names)

            cancel_command = [
                docker, base[0], "--progress", "quiet", *base[1:], "run", "--name", cancel_name,
                "--no-deps", "migration", *_psql_arguments(admin_user, "SELECT pg_sleep(30);")
            ]
            cancel_process = subprocess.Popen(
                cancel_command, cwd=ROOT, env=env, text=True, encoding="utf-8",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            created_names.append(cancel_name)
            _wait_running(docker, cancel_name)
            _run(docker, ["stop", "--time", "1", cancel_name])
            cancel_stdout, cancel_stderr = cancel_process.communicate(timeout=15)
            cancelled_state = json.loads(_run(docker, ["inspect", cancel_name]).stdout)[0]["State"]
            cancel_ok = cancel_process.returncode != 0 and cancelled_state.get("Status") == "exited"
            _check(
                checks,
                "host-cancellation-distinct",
                cancel_ok,
                {"lifecycle":"cancelled","verification_verdict":None,"exit_code":cancel_process.returncode,"container_exit_code":cancelled_state.get("ExitCode"),"output_digest":_sha((cancel_stdout + cancel_stderr).encode())},
            )
            _remove_completed(docker, created_names)

            _run(docker, ["restart", database_name])
            _wait_healthy(docker, database_name)
            rows_after_restart = _query_rows(docker, base, env, project, admin_user, created_names, "after-restart")
            expected_after_restart = sorted(
                [*expected_rows, {key: expected_recovery[key] for key in ("run_id", "runner", "input_digest", "result_digest")}],
                key=lambda item: (item["run_id"], item["runner"]),
            )
            _check(checks, "restart-persistence", rows_after_restart == expected_after_restart, rows_after_restart)
            _remove_completed(docker, created_names)
            project_containers = [
                line for line in _run(docker, ["ps", "-a", "--format", "{{.Names}}", "--filter", f"name={project}"]).stdout.splitlines()
                if line
            ]
            _check(checks, "orphan-detection", project_containers == [database_name], project_containers)
            evidence.update({
                "fresh_rows": rows,
                "restart_rows": rows_after_restart,
                "python_result": actual_python,
                "node_result": actual_node,
                "recovery_result": actual_recovery,
            })
        finally:
            for name in [migration_name, python_name, node_name, python_invalid_name, node_invalid_name, python_failed_name, python_recovery_name, cancel_name, *created_names]:
                subprocess.run([docker, "rm", "-f", name], cwd=ROOT, capture_output=True, check=False)
            cleanup = subprocess.run(
                [docker, *base, "down", "--volumes", "--remove-orphans"], cwd=ROOT, env=env,
                text=True, encoding="utf-8", capture_output=True, timeout=180, check=False,
            )
            cleanup_exit_code = cleanup.returncode

        containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        after_volumes = _volume_names(docker)
        protected_ok = protected.issubset(after_volumes)
        teardown_ok = cleanup_exit_code == 0 and not containers_left and not network_left and volume not in after_volumes
        _check(checks, "protected-volumes-unchanged", protected_ok, {"protected":sorted(protected),"present":sorted(protected & after_volumes)})
        _check(checks, "disposable-teardown", teardown_ok, {"cleanup_exit_code":cleanup_exit_code,"containers":containers_left,"network":network_left,"volume_exists":volume in after_volumes})
        if not protected_ok or not teardown_ok:
            raise TopologyError("IS_RELIABILITY_TEARDOWN", "reliability teardown or retained-volume custody differs from the contract")
        verdict = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
        return {
            "schema_version": "incidentseal-reliability-surface-probe/v1",
            "verdict": verdict,
            "mode": "platform-validation",
            "claim_scope": "disposable-topology-reliability-only",
            "project_name": project,
            "contract_digest": _sha256_file(CONTRACT_PATH),
            "images": image_receipts,
            "checks": checks,
            "inspections": inspections,
            "evidence": evidence,
            "protected_volumes": sorted(protected),
            "disposable_volume_removed": True,
            "containers_removed": True,
            "network_removed": True,
            "runtime_started": True,
            "static_validation": static.data,
        }
