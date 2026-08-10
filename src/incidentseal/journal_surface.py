"""Host-owned durable journal persistence, streaming, and disposable real probe."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from .database import _wait_healthy
from .journal import (
    JournalError,
    canonical_record,
    event_from_canonical_bytes,
    lifecycle_exit,
    validate_implementation_lock,
    validate_record,
    validate_run_id,
)
from .manifest import canonical_bytes, strict_load_bytes
from .reliability_surface import _load_retained_volume_lock, _volume_names
from .runtime import _build_images, _compose_args, _compose_env, _inspect_container, _run, _runtime_lock_images
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


VECTORS = ROOT / "fixtures" / "journal" / "vectors.json"
SQL_ERROR_RE = re.compile(r"\b(IS_JOURNAL_[A-Z0-9_]+)\b")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _database_psql(docker: str, container: str, sql: str, *, user: str = "incidentseal_admin") -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [
                docker, "exec", "--user", "70:70", container, "/usr/bin/psql",
                "--host=127.0.0.1", f"--username={user}", "--dbname=incidentseal",
                "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align", f"--command={sql}",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise JournalError("IS_JOURNAL_DATABASE", "PostgreSQL journal query could not execute", io_error=True) from error


def _journal_error(completed: subprocess.CompletedProcess[str], fallback: str) -> JournalError:
    combined = (completed.stderr + completed.stdout).strip()
    match = SQL_ERROR_RE.search(combined)
    code = match.group(1) if match else fallback
    message = combined.splitlines()[-1][:500] if combined else "PostgreSQL rejected the journal operation"
    return JournalError(code, message)


def _append_bytes(docker: str, container: str, raw: bytes) -> dict[str, Any]:
    try:
        parsed = strict_load_bytes(raw)
        event_raw = canonical_bytes(parsed["event"])
    except (KeyError, TypeError, ValueError) as error:
        raise JournalError("IS_JOURNAL_SCHEMA", "journal record bytes do not contain an event") from error
    sql = (
        "SELECT row_to_json(result)::text FROM "
        f"public.incidentseal_append_event(decode('{raw.hex()}','hex'),decode('{event_raw.hex()}','hex')) AS result;"
    )
    completed = _database_psql(docker, container, sql)
    if completed.returncode != 0:
        raise _journal_error(completed, "IS_JOURNAL_DATABASE")
    lines = [line for line in completed.stdout.splitlines() if line]
    if len(lines) != 1:
        raise JournalError("IS_JOURNAL_DATABASE", "append did not return exactly one result")
    try:
        result = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise JournalError("IS_JOURNAL_DATABASE", "append result is not JSON") from error
    expected = {
        "disposition", "run_id", "sequence", "idempotency_key", "event_digest", "link_digest",
        "event_count", "root_digest", "lifecycle", "verdict", "terminal"
    }
    if not isinstance(result, dict) or set(result) != expected:
        raise JournalError("IS_JOURNAL_DATABASE", "append result shape differs")
    return {"schema_version": "incidentseal-event-journal-result/v1", **result}


def append_record(docker: str, container: str, record_value: Any) -> dict[str, Any]:
    """Internal host-only append; no agent-facing mutation command calls this directly."""

    validate_implementation_lock()
    record, raw = canonical_record(record_value)
    result = _append_bytes(docker, container, raw)
    event = record["event"]
    for name, expected in {
        "run_id": event["run_id"],
        "sequence": event["sequence"],
        "idempotency_key": record["idempotency_key"],
        "event_digest": record["event_digest"],
        "link_digest": record["link_digest"],
        "root_digest": record["link_digest"],
        "lifecycle": event["lifecycle"],
        "verdict": event["verdict"],
        "terminal": event["terminal"],
    }.items():
        if result.get(name) != expected:
            raise JournalError("IS_JOURNAL_DATABASE", f"append result field differs: {name}")
    if result.get("event_count") != event["sequence"] + 1 or result.get("disposition") not in {"inserted", "replayed"}:
        raise JournalError("IS_JOURNAL_DATABASE", "append result count or disposition differs")
    return result


def _database_candidates(docker: str) -> list[str]:
    contract_digest = _sha256_file(CONTRACT_PATH)
    contract = _load(CONTRACT_PATH)
    database_lock = _runtime_lock_images(contract_digest)["database"]
    completed = _run(
        docker,
        ["ps", "-q", "--filter", f"label=dev.incidentseal.contract-digest={contract_digest}"],
    )
    candidates: list[str] = []
    for container_id in completed.stdout.splitlines():
        if not container_id:
            continue
        value = json.loads(_run(docker, ["inspect", container_id]).stdout)[0]
        labels = value.get("Config", {}).get("Labels") or {}
        host = value.get("HostConfig", {})
        if labels.get("com.docker.compose.service") != "database":
            continue
        if (
            value.get("Image") != database_lock.get("image_id")
            or value.get("Config", {}).get("User") != "70:70"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or "ALL" not in (host.get("CapDrop") or [])
            or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
        ):
            raise JournalError("IS_JOURNAL_RUNTIME", "candidate journal database differs from the runtime lock")
        candidates.append(value["Name"].lstrip("/"))
    return sorted(candidates)


def stream_events(run_id_value: str) -> tuple[list[bytes], int]:
    """Read exact retained event bytes from one unambiguous active journal database."""

    validate_implementation_lock()
    run_id = validate_run_id(run_id_value)
    docker = _docker_executable()
    candidates = _database_candidates(docker)
    if not candidates:
        raise JournalError("IS_JOURNAL_RUNTIME", "no active digest-bound journal database is available", io_error=True)
    matches: list[tuple[str, list[str]]] = []
    for container in candidates:
        sql = (
            "SELECT encode(event_bytes,'hex') FROM public.incidentseal_run_events "
            f"WHERE run_id='{run_id}'::uuid ORDER BY sequence;"
        )
        completed = _database_psql(docker, container, sql)
        if completed.returncode != 0:
            raise _journal_error(completed, "IS_JOURNAL_DATABASE")
        lines = [line for line in completed.stdout.splitlines() if line]
        if lines:
            matches.append((container, lines))
    if not matches:
        return [], 11
    if len(matches) != 1:
        raise JournalError("IS_JOURNAL_CONFLICT", "run exists in more than one active journal database")
    raw_events: list[bytes] = []
    events: list[dict[str, Any]] = []
    for sequence, encoded in enumerate(matches[0][1]):
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as error:
            raise JournalError("IS_JOURNAL_DATABASE", "retained event encoding is invalid") from error
        event = event_from_canonical_bytes(raw, run_id=run_id, sequence=sequence)
        raw_events.append(raw)
        events.append(event)
    return raw_events, lifecycle_exit(events[-1])


def run_events_cli(arguments: list[str]) -> int:
    """Implement the JSONL-only read surface without mixing envelopes into stdout."""

    run_id: str | None = None
    jsonl = False
    index = 0
    try:
        while index < len(arguments):
            token = arguments[index]
            if token == "--jsonl":
                if jsonl:
                    raise JournalError("IS_USAGE", "--jsonl may be specified only once")
                jsonl = True
                index += 1
                continue
            if token == "--run-id":
                if run_id is not None or index + 1 >= len(arguments) or not arguments[index + 1]:
                    raise JournalError("IS_USAGE", "--run-id requires exactly one value")
                run_id = arguments[index + 1]
                index += 2
                continue
            raise JournalError("IS_USAGE", f"unknown argument: {token}")
        if not jsonl or run_id is None:
            raise JournalError("IS_USAGE", "run events requires --run-id ID --jsonl")
        raw_events, exit_code = stream_events(run_id)
        for raw in raw_events:
            sys.stdout.buffer.write(raw + b"\n")
        sys.stdout.buffer.flush()
        return exit_code
    except TopologyError as error:
        code = 64 if error.code == "IS_USAGE" or error.code == "IS_JOURNAL_SCHEMA" else (74 if error.io_error else 12)
        sys.stderr.write(f"{error.code}: {str(error)[:1000]}\n")
        sys.stderr.flush()
        return code


def _record_for_event(event: dict[str, Any], previous: str) -> dict[str, Any]:
    event_digest = _digest(canonical_bytes(event))
    idempotency = _digest(
        canonical_bytes(
            {
                "schema_version": "incidentseal-event-idempotency/v1",
                "run_id": event["run_id"],
                "sequence": event["sequence"],
                "event_digest": event_digest,
                "previous_link_digest": previous,
            }
        )
    )
    link = _digest(
        canonical_bytes(
            {
                "schema_version": "incidentseal-event-link/v1",
                "sequence": event["sequence"],
                "event_digest": event_digest,
                "previous_link_digest": previous,
            }
        )
    )
    return {
        "schema_version": "incidentseal-event-journal-record/v1",
        "idempotency_key": idempotency,
        "event_digest": event_digest,
        "previous_link_digest": previous,
        "link_digest": link,
        "event": event,
    }


def _expect_error(callable_value: Any, code: str) -> dict[str, Any]:
    try:
        callable_value()
    except JournalError as error:
        if error.code != code:
            raise TopologyError("IS_JOURNAL_PROBE", f"expected {code}, observed {error.code}") from error
        return {"expected_error": code, "observed_error": error.code}
    raise TopologyError("IS_JOURNAL_PROBE", f"expected journal rejection {code}")


def _run_stream_cli(run_id: str) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if os.name == "nt":
        command = [environment.get("COMSPEC", "cmd.exe"), "/d", "/c", str(ROOT / "incidentseal.cmd")]
    else:
        command = [str(ROOT / "incidentseal")]
    return subprocess.run(
        [*command, "run", "events", "--run-id", run_id, "--jsonl"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _volume_snapshot(docker: str, names: set[str]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for name in sorted(names):
        value = json.loads(_run(docker, ["volume", "inspect", name]).stdout)[0]
        stable = {
            "Name": value.get("Name"),
            "CreatedAt": value.get("CreatedAt"),
            "Driver": value.get("Driver"),
            "Labels": value.get("Labels"),
            "Options": value.get("Options"),
            "Scope": value.get("Scope"),
        }
        snapshot[name] = _digest(canonical_bytes(stable))
    return snapshot


def journal_probe() -> dict[str, Any]:
    """Exercise durable journal semantics in the fixed disposable PostgreSQL custody."""

    static = validate_platform_topology()
    validate_implementation_lock()
    docker = _docker_executable()
    volume_lock, protected = _load_retained_volume_lock(docker)
    protected_before = _volume_snapshot(docker, protected)
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    services = {item["id"]: item for item in contract["services"]}
    admin_user = services["database"]["environment"]["POSTGRES_USER"]
    runner_user = services["python-runner"]["environment"]["PGUSER"]
    disposable = volume_lock["disposable_project"]
    project = disposable["name"]
    volume = disposable["volume"]
    network = f"{project}_data"
    database = f"{project}-database-1"
    migration = f"{project}-migration-journal"
    checks: list[dict[str, Any]] = []
    results: dict[str, Any] = {}

    def check(check_id: str, passed: bool, observed: Any) -> None:
        checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})

    with tempfile.TemporaryDirectory(prefix="incidentseal-journal-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        if ROOT == custody or ROOT in custody.parents or any(part.casefold() == "onedrive" for part in custody.parts):
            raise TopologyError("IS_JOURNAL_CUSTODY", "journal probe custody overlaps a forbidden root")
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        (custody / "input" / "request.json").write_text("{}\n", encoding="utf-8")
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, _, _ = _compose_env(contract, identities, custody)
        env["INCIDENTSEAL_PROJECT_NAME"] = project
        env["INCIDENTSEAL_RUN_ID"] = "isrun-4444444444444444"
        base = _compose_args(env_file)

        before_volumes = _volume_names(docker)
        stale_containers = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        stale_network = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        if stale_containers or stale_network or volume in before_volumes:
            raise TopologyError("IS_JOURNAL_STALE", "disposable journal resources already exist")
        cleanup_exit: int | None = None
        try:
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database)
            database_inspection = _inspect_container(docker, database, identities["database"], "70:70", network)
            _run(docker, [*base, "run", "--name", migration, "--no-deps", "migration"], env=env)
            migration_inspection = _inspect_container(docker, migration, identities["migration"], "70:70", network)
            _run(docker, ["rm", "-f", migration])
            check("fresh-disposable-bootstrap", volume in _volume_names(docker), {"volume": volume, "healthy": True})

            vectors = strict_load_bytes(VECTORS.read_bytes())
            expected_exits = {"completed-pass": 0, "stale-authority": 22, "superseded-attempt": 23}
            inserted = 0
            replayed = 0
            streams: dict[str, Any] = {}
            for case in vectors["cases"]:
                for record in case["records"]:
                    outcome = append_record(docker, database, record)
                    if outcome["disposition"] != "inserted":
                        raise TopologyError("IS_JOURNAL_PROBE", "new vector record did not insert")
                    inserted += 1
                replay = append_record(docker, database, deepcopy(case["records"][-1]))
                if replay["disposition"] != "replayed" or replay["event_count"] != len(case["records"]):
                    raise TopologyError("IS_JOURNAL_PROBE", "exact replay changed journal state")
                replayed += 1
                run_id = case["records"][-1]["event"]["run_id"]
                streamed = _run_stream_cli(run_id)
                expected = b"".join(canonical_bytes(item["event"]) + b"\n" for item in case["records"])
                stream_ok = streamed.returncode == expected_exits[case["id"]] and streamed.stdout == expected and not streamed.stderr
                check(f"run-events-{case['id']}", stream_ok, {"exit_code": streamed.returncode, "stream_digest": _digest(streamed.stdout), "lines": streamed.stdout.count(b"\n")})
                streams[case["id"]] = {"run_id": run_id, "exit_code": streamed.returncode, "stream_digest": _digest(streamed.stdout)}
            check("transactional-insert-and-replay", inserted == 7 and replayed == 3, {"inserted": inserted, "replayed": replayed})

            first = vectors["cases"][0]["records"][0]
            altered = deepcopy(first)
            altered["event"]["payload"]["attempt"] = 99
            idempotency_conflict = _expect_error(
                lambda: _append_bytes(docker, database, canonical_bytes(altered)), "IS_JOURNAL_CONFLICT"
            )
            sequence_event = deepcopy(first["event"])
            sequence_event.update({"event_id": "223e4567-e89b-42d3-a456-426614174111", "occurred_at_utc": "2026-08-09T23:51:00Z", "payload": {"attempt": 11, "claim_id": "release.ready"}})
            sequence_conflict = _expect_error(
                lambda: append_record(docker, database, _record_for_event(sequence_event, first["previous_link_digest"])),
                "IS_JOURNAL_CONFLICT",
            )
            event_id_event = deepcopy(first["event"])
            event_id_event.update({"run_id": "223e4567-e89b-42d3-a456-426614174500", "occurred_at_utc": "2026-08-09T23:51:01Z", "payload": {"attempt": 12, "claim_id": "release.ready"}})
            event_id_conflict = _expect_error(
                lambda: append_record(docker, database, _record_for_event(event_id_event, first["previous_link_digest"])),
                "IS_JOURNAL_CONFLICT",
            )
            completed = vectors["cases"][0]["records"][-1]
            terminal_event = deepcopy(completed["event"])
            terminal_event.update({
                "event_id": "223e4567-e89b-42d3-a456-426614174104", "sequence": 3,
                "occurred_at_utc": "2026-08-09T23:51:02Z", "event_type": "evidence.recorded",
                "lifecycle": "running", "verdict": None, "terminal": False,
                "payload": {"kind": "late"},
            })
            terminal_rejection = _expect_error(
                lambda: append_record(docker, database, _record_for_event(terminal_event, completed["link_digest"])),
                "IS_JOURNAL_TERMINAL",
            )
            authority_start_event = deepcopy(first["event"])
            authority_start_event.update({
                "event_id": "223e4567-e89b-42d3-a456-426614174601",
                "run_id": "223e4567-e89b-42d3-a456-426614174600",
                "occurred_at_utc": "2026-08-09T23:51:03Z",
                "payload": {"attempt": 13, "claim_id": "release.ready"},
            })
            authority_start = _record_for_event(authority_start_event, first["previous_link_digest"])
            append_record(docker, database, authority_start)
            authority_running_event = deepcopy(authority_start_event)
            authority_running_event.update({
                "event_id": "223e4567-e89b-42d3-a456-426614174602", "sequence": 1,
                "occurred_at_utc": "2026-08-09T23:51:04Z", "event_type": "run.started",
                "lifecycle": "running", "payload": {"host": "incidentseal"},
            })
            authority_running = _record_for_event(authority_running_event, authority_start["link_digest"])
            append_record(docker, database, authority_running)
            authority_event = deepcopy(authority_running_event)
            authority_event.update({
                "event_id": "223e4567-e89b-42d3-a456-426614174603", "sequence": 2,
                "occurred_at_utc": "2026-08-09T23:51:05Z", "event_type": "evidence.recorded",
                "manifest_digest": "sha256:" + "2" * 64, "approval_digest": "sha256:" + "2" * 64,
                "payload": {"kind": "drift"},
            })
            authority_rejection = _expect_error(
                lambda: append_record(docker, database, _record_for_event(authority_event, authority_running["link_digest"])),
                "IS_JOURNAL_AUTHORITY",
            )
            check(
                "database-conflict-and-state-rejection", True,
                {"idempotency": idempotency_conflict, "sequence": sequence_conflict, "event_id": event_id_conflict, "terminal": terminal_rejection, "authority": authority_rejection},
            )

            for operation, sql in {
                "update": "UPDATE public.incidentseal_run_events SET lifecycle='running' WHERE sequence=0;",
                "delete": "DELETE FROM public.incidentseal_run_events WHERE sequence=0;",
                "truncate": "TRUNCATE public.incidentseal_run_events;",
            }.items():
                denied = _database_psql(docker, database, sql)
                match = SQL_ERROR_RE.search(denied.stderr + denied.stdout)
                check(f"immutable-{operation}-denied", denied.returncode != 0 and match is not None and match.group(1) == "IS_JOURNAL_IMMUTABLE", {"exit_code": denied.returncode, "error": match.group(1) if match else None})
            runner_read = _database_psql(docker, database, "SELECT count(*) FROM public.incidentseal_run_events;", user=runner_user)
            check("runner-table-read-denied", runner_read.returncode != 0 and "permission denied" in (runner_read.stderr + runner_read.stdout).lower(), {"exit_code": runner_read.returncode})

            count = _database_psql(docker, database, "SELECT count(*) FROM public.incidentseal_run_events;")
            check("retained-row-count", count.returncode == 0 and count.stdout.strip() == "9", count.stdout.strip())
            _run(docker, ["restart", database])
            _wait_healthy(docker, database)
            completed_run = vectors["cases"][0]["records"][-1]["event"]["run_id"]
            after_restart = _run_stream_cli(completed_run)
            expected_restart = b"".join(canonical_bytes(item["event"]) + b"\n" for item in vectors["cases"][0]["records"])
            check("restart-persistence-and-stream", after_restart.returncode == 0 and after_restart.stdout == expected_restart and not after_restart.stderr, {"exit_code": after_restart.returncode, "stream_digest": _digest(after_restart.stdout)})
            results = {
                "inserted_records": inserted,
                "exact_replays": replayed,
                "streams": streams,
                "database_inspection": database_inspection,
                "migration_inspection": migration_inspection,
            }
        finally:
            subprocess.run([docker, "rm", "-f", migration], cwd=ROOT, capture_output=True, check=False)
            cleanup = subprocess.run(
                [docker, *base, "down", "--volumes", "--remove-orphans"],
                cwd=ROOT, env=env, text=True, encoding="utf-8", capture_output=True, timeout=180, check=False,
            )
            cleanup_exit = cleanup.returncode

    after_volumes = _volume_names(docker)
    protected_after = _volume_snapshot(docker, protected)
    containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
    network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
    custody_ok = protected_before == protected_after and protected.issubset(after_volumes)
    teardown_ok = cleanup_exit == 0 and not containers_left and not network_left and volume not in after_volumes
    check("protected-volume-identities-unchanged", custody_ok, {"before": protected_before, "after": protected_after})
    check("disposable-teardown", teardown_ok, {"cleanup_exit_code": cleanup_exit, "containers": containers_left, "network": network_left, "volume_exists": volume in after_volumes})
    if not custody_ok or not teardown_ok:
        raise TopologyError("IS_JOURNAL_TEARDOWN", "journal probe teardown or protected-volume identity differs")
    verdict = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    return {
        "schema_version": "incidentseal-event-journal-probe/v1",
        "verdict": verdict,
        "mode": "platform-validation",
        "claim_scope": "synthetic-event-journal-only",
        "project_name": project,
        "contract_digest": _sha256_file(CONTRACT_PATH),
        "journal_implementation_lock_digest": validate_implementation_lock(),
        "images": image_receipts,
        "checks": checks,
        "results": results,
        "protected_volumes": sorted(protected),
        "disposable_volume_removed": True,
        "containers_removed": True,
        "network_removed": True,
        "approval_accessed": False,
        "workflow_executed": False,
        "runtime_started": True,
        "static_validation": static.data,
    }
