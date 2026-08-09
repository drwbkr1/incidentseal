"""Host-owned real Node application runner probe."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .database import _last_json, _run_psql, _wait_healthy
from .runtime import _build_images, _compose_args, _compose_env, _inspect_container, _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


VALID_FIXTURE = ROOT / "fixtures" / "topology" / "runner-request.valid.json"
INVALID_FIXTURE = ROOT / "fixtures" / "topology" / "runner-request.invalid.extra.json"
SENSITIVE_NAME_RE = re.compile(r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|DOCKER_HOST)(?:_|$)")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_text(value: Any) -> str:
    if isinstance(value, dict):
        keys = sorted(value, key=lambda item: item.encode("utf-16-be", errors="surrogatepass"))
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _canonical_text(value[key]) for key in keys) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _expected_result(request: dict[str, Any], runner: str) -> dict[str, Any]:
    input_digest = _sha(_canonical_text(request).encode("utf-8"))
    return {
        "schema_version": "incidentseal-runner-result/v1",
        "run_id": request["run_id"],
        "runner": runner,
        "input_digest": input_digest,
        "result_digest": _sha((input_digest + "|" + runner).encode("utf-8")),
        "database_verified": True,
    }


def _raw_compose(
    docker: str,
    base: list[str],
    env: dict[str, str],
    arguments: list[str],
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [docker, base[0], "--progress", "quiet", *base[1:], *arguments],
            cwd=ROOT,
            env=env,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TopologyError("IS_NODE_RUNTIME", "Node runner command could not execute", io_error=True) from error


def _check(checks: list[dict[str, Any]], check_id: str, passed: bool, observed: Any) -> None:
    checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})


def _remove_completed(docker: str, names: list[str]) -> None:
    for name in dict.fromkeys(names):
        _run(docker, ["rm", "-f", name])
    names.clear()


def _container_isolation(docker: str, name: str, custody: Path, network: str) -> dict[str, Any]:
    value = json.loads(_run(docker, ["inspect", name]).stdout)[0]
    mounts = {item.get("Destination"): item for item in value.get("Mounts", [])}
    input_mount = mounts.get("/incidentseal/input", {})
    output_mount = mounts.get("/incidentseal/output", {})
    environment_names = sorted(item.split("=", 1)[0] for item in value["Config"].get("Env", []))
    sensitive_names = [name for name in environment_names if SENSITIVE_NAME_RE.search(name)]
    input_source = Path(str(input_mount.get("Source", ""))).resolve(strict=False)
    output_source = Path(str(output_mount.get("Source", ""))).resolve(strict=False)
    expected_input = (custody / "input").resolve(strict=True)
    expected_output = (custody / "node-output").resolve(strict=True)
    network_model = json.loads(_run(docker, ["network", "inspect", network]).stdout)[0]
    passed = all(
        [
            input_mount.get("RW") is False,
            output_mount.get("RW") is True,
            input_source == expected_input,
            output_source == expected_output,
            not sensitive_names,
            network_model.get("Internal") is True,
            not any("docker.sock" in str(item).lower() or "docker_engine" in str(item).lower() for item in value.get("Mounts", [])),
            all(part.casefold() != "onedrive" for part in input_source.parts),
            all(part.casefold() != "onedrive" for part in output_source.parts),
        ]
    )
    if not passed:
        raise TopologyError("IS_NODE_ISOLATION", "Node runner staged custody or isolation differs from the contract")
    return {
        "input_read_only": True,
        "output_write_only_by_convention": True,
        "input_source_outside_repository": ROOT not in input_source.parents and input_source != ROOT,
        "output_source_outside_repository": ROOT not in output_source.parents and output_source != ROOT,
        "sensitive_environment_names": sensitive_names,
        "internal_network": True,
        "docker_endpoint_absent": True,
    }


def node_probe() -> dict[str, Any]:
    static = validate_platform_topology()
    docker = _docker_executable()
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    services = {item["id"]: item for item in contract["services"]}
    admin_user = services["database"]["environment"]["POSTGRES_USER"]
    runner_user = services["node-runner"]["environment"]["PGUSER"]

    with tempfile.TemporaryDirectory(prefix="incidentseal-node-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        if ROOT in custody.parents or custody == ROOT or any(part.casefold() == "onedrive" for part in custody.parts):
            raise TopologyError("IS_NODE_CUSTODY", "Node probe custody overlaps a forbidden root")
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        request_path = custody / "input" / "request.json"
        output_path = custody / "node-output" / "result.json"
        request_path.write_bytes(VALID_FIXTURE.read_bytes())
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, project, run_id = _compose_env(contract, identities, custody)
        base = _compose_args(env_file)
        network = f"{project}_data"
        database_name = f"{project}-database-1"
        volume = f"{project}_database-data"
        migration_name = f"{project}-migration-node-surface"
        positive_name = f"{project}-node-real"
        invalid_name = f"{project}-node-invalid"
        created_names: list[str] = []
        checks: list[dict[str, Any]] = []
        inspections: list[dict[str, Any]] = []
        evidence: dict[str, Any] = {}

        if _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip():
            raise TopologyError("IS_NODE_STALE", "pre-existing Node probe container conflicts with the run")
        if _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip():
            raise TopologyError("IS_NODE_STALE", "pre-existing Node probe network conflicts with the run")
        if not _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip():
            raise TopologyError("IS_NODE_STALE", "the exact verified database volume is unavailable")

        try:
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database_name)
            inspections.append(_inspect_container(docker, database_name, identities["database"], "70:70", network))
            created_names.append(migration_name)
            _run(docker, [*base, "run", "--name", migration_name, "--no-deps", "migration"], env=env)
            inspections.append(_inspect_container(docker, migration_name, identities["migration"], "70:70", network))
            _remove_completed(docker, created_names)

            valid_request_bytes = request_path.read_bytes()
            valid_request = json.loads(valid_request_bytes)
            expected = _expected_result(valid_request, "node")
            expected_python = _expected_result(valid_request, "python")
            positive = _raw_compose(
                docker,
                base,
                env,
                ["run", "--name", positive_name, "--no-deps", "node-runner"],
            )
            created_names.append(positive_name)
            _check(
                checks,
                "node-command-exit",
                positive.returncode == 0 and not positive.stderr.strip(),
                {"exit_code": positive.returncode, "stdout_digest": _sha(positive.stdout.encode()), "stderr_digest": _sha(positive.stderr.encode())},
            )
            inspections.append(_inspect_container(docker, positive_name, identities["node-runner"], "65532:65532", network))
            isolation = _container_isolation(docker, positive_name, custody, network)
            _check(checks, "runtime-isolation", True, isolation)
            input_unchanged = request_path.read_bytes() == valid_request_bytes
            _check(checks, "staged-input-read-only", input_unchanged, {"sha256": _sha(request_path.read_bytes())})

            actual: dict[str, Any] | None = None
            if output_path.is_file():
                try:
                    actual = json.loads(output_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    actual = None
            output_ok = actual == expected and set(custody.joinpath("node-output").iterdir()) == {output_path}
            _check(checks, "result-receipt", output_ok, actual)
            evidence["result"] = actual
            evidence["result_file_digest"] = _sha(output_path.read_bytes()) if output_path.is_file() else None

            row_sql = f"""SELECT json_build_object(
              'node', COALESCE((SELECT json_build_object(
                'run_id', run_id, 'runner', runner, 'input_digest', input_digest, 'result_digest', result_digest
              ) FROM public.verification_results
              WHERE run_id = '{valid_request['run_id']}' AND runner = 'node'), json_build_object('missing', true)),
              'python', COALESCE((SELECT json_build_object(
                'run_id', run_id, 'runner', runner, 'input_digest', input_digest, 'result_digest', result_digest
              ) FROM public.verification_results
              WHERE run_id = '{valid_request['run_id']}' AND runner = 'python'), json_build_object('missing', true))
            )::text;"""
            rows = _last_json(
                _run_psql(docker, base, env, f"{project}-query-node-row", admin_user, row_sql, created_names)
            )
            node_row = rows.get("node") if isinstance(rows, dict) else None
            python_row = rows.get("python") if isinstance(rows, dict) else None
            expected_node_row = {key: expected[key] for key in ("run_id", "runner", "input_digest", "result_digest")}
            expected_python_row = {key: expected_python[key] for key in ("run_id", "runner", "input_digest", "result_digest")}
            _check(checks, "database-row", node_row == expected_node_row, node_row)
            cross_runner_ok = python_row == expected_python_row and node_row == expected_node_row and python_row["input_digest"] == node_row["input_digest"]
            _check(
                checks,
                "cross-runner-consistency",
                cross_runner_ok,
                {"python": python_row, "node": node_row},
            )
            evidence["database_row"] = node_row
            evidence["cross_runner_rows"] = {"python": python_row, "node": node_row}
            _remove_completed(docker, created_names)

            if output_path.exists():
                output_path.unlink()
            invalid_bytes = INVALID_FIXTURE.read_bytes()
            invalid_request = json.loads(invalid_bytes)
            request_path.write_bytes(invalid_bytes)
            invalid = _raw_compose(
                docker,
                base,
                env,
                ["run", "--name", invalid_name, "--no-deps", "node-runner"],
            )
            created_names.append(invalid_name)
            invalid_text = (invalid.stdout + invalid.stderr).strip()
            inspections.append(_inspect_container(docker, invalid_name, identities["node-runner"], "65532:65532", network))
            invalid_rejected = invalid.returncode != 0 and "request shape is invalid" in invalid_text and not output_path.exists()
            _check(
                checks,
                "invalid-input-rejected",
                invalid_rejected,
                {"exit_code": invalid.returncode, "output_digest": _sha(invalid_text.encode()), "result_file_exists": output_path.exists()},
            )
            _check(
                checks,
                "invalid-input-read-only",
                request_path.read_bytes() == invalid_bytes,
                {"sha256": _sha(request_path.read_bytes())},
            )
            _remove_completed(docker, created_names)
            absent_sql = f"""SELECT json_build_object('row_count', count(*))::text
              FROM public.verification_results WHERE run_id = '{invalid_request['run_id']}' AND runner = 'node';"""
            absent = _last_json(
                _run_psql(docker, base, env, f"{project}-query-node-invalid", admin_user, absent_sql, created_names)
            )
            _check(checks, "invalid-input-no-database-row", absent == {"row_count": 0}, absent)
            evidence["invalid_output_digest"] = _sha(invalid_text.encode())
        finally:
            for name in [migration_name, positive_name, invalid_name, *created_names]:
                subprocess.run([docker, "rm", "-f", name], cwd=ROOT, capture_output=True, check=False)
            subprocess.run([docker, *base, "down", "--remove-orphans"], cwd=ROOT, env=env, capture_output=True, check=False)

        containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        volume_left = _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip()
        teardown_ok = not containers_left and not network_left and volume_left == volume
        _check(checks, "teardown", teardown_ok, {"containers": containers_left, "network": network_left, "volume": volume_left})
        if not teardown_ok:
            raise TopologyError("IS_NODE_TEARDOWN", "Node probe teardown or retained volume differs from the contract")
        verdict = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
        return {
            "schema_version": "incidentseal-node-surface-probe/v1",
            "verdict": verdict,
            "mode": "platform-validation",
            "claim_scope": "node-application-runner-and-cross-runner-consistency",
            "project_name": project,
            "run_id": run_id,
            "contract_digest": _sha256_file(CONTRACT_PATH),
            "database_user": runner_user,
            "images": image_receipts,
            "checks": checks,
            "inspections": inspections,
            "evidence": evidence,
            "retained_volume": volume,
            "containers_removed": True,
            "network_removed": True,
            "runtime_started": True,
            "static_validation": static.data,
        }
