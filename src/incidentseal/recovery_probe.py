"""Real disposable Docker/PostgreSQL probe for the host-only recovery executor."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from .database import _wait_healthy
from .journal import GENESIS, JournalError, validate_implementation_lock as validate_journal_lock
from .journal_surface import (
    _database_psql,
    _journal_error,
    _record_for_event,
    _run_stream_cli,
    _volume_snapshot,
    append_record,
)
from .manifest import canonical_bytes, strict_load_bytes
from .recovery import RecoveryError
from .recovery_surface import (
    RecoveryBackend,
    RecoveryExecutionError,
    RecoveryExecutor,
    RecoveryInterrupted,
    _deterministic_uuid,
)
from .reliability_surface import _load_retained_volume_lock, _volume_names
from .runtime import _build_images, _compose_args, _compose_env, _inspect_container, _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


IMPLEMENTATION_LOCK = ROOT / "requirements" / "recovery-implementation.lock.json"
SQL_ERROR_RE = re.compile(r"\b(IS_RECOVERY_[A-Z0-9_]+)\b")
EXPECTED_IMPLEMENTATION_PATHS = (
    "containers/migration/001-schema.sql",
    "docs/cli-contract.md",
    "docs/recovery-implementation.md",
    "fixtures/recovery/implementation-mutations.json",
    "requirements/recovery-contract.lock.json",
    "scripts/test_recovery_implementation_mutations.py",
    "scripts/validate_recovery_implementation.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/recovery.py",
    "src/incidentseal/recovery_probe.py",
    "src/incidentseal/recovery_surface.py",
    "tests/test_recovery.py",
    "tests/test_recovery_surface.py",
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _shift(value: str, seconds: int) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_recovery_implementation_lock() -> str:
    try:
        lock = strict_load_bytes(IMPLEMENTATION_LOCK.read_bytes())
    except (OSError, ValueError) as error:
        raise RecoveryExecutionError("IS_RECOVERY_IMPLEMENTATION", "recovery implementation lock is unreadable") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-recovery-implementation-lock/v1":
        raise RecoveryExecutionError("IS_RECOVERY_IMPLEMENTATION", "recovery implementation lock version differs")
    entries = lock.get("files")
    if not isinstance(entries, list) or tuple(item.get("path") for item in entries if isinstance(item, dict)) != EXPECTED_IMPLEMENTATION_PATHS:
        raise RecoveryExecutionError("IS_RECOVERY_IMPLEMENTATION", "recovery implementation lock scope differs")
    for entry in entries:
        path = ROOT / str(entry.get("path", ""))
        try:
            observed = _digest(path.read_bytes())
        except OSError as error:
            raise RecoveryExecutionError("IS_RECOVERY_IMPLEMENTATION", f"locked recovery file is unavailable: {path.name}") from error
        if observed != entry.get("sha256"):
            raise RecoveryExecutionError("IS_RECOVERY_IMPLEMENTATION", f"recovery implementation drift: {entry.get('path')}")
    return _digest(IMPLEMENTATION_LOCK.read_bytes())


class DockerRecoveryBackend(RecoveryBackend):
    """Exact Docker and PostgreSQL adapter used only by the host CLI."""

    def __init__(
        self,
        docker: str,
        database_container: str,
        python_image_id: str,
        state_root: Path,
    ) -> None:
        self.docker = docker
        self.database = database_container
        self.python_image_id = python_image_id
        self.state_root = state_root

    def _one_json(self, sql: str, code: str = "IS_RECOVERY_DATABASE") -> dict[str, Any]:
        completed = _database_psql(self.docker, self.database, sql)
        if completed.returncode != 0:
            match = SQL_ERROR_RE.search(completed.stderr + completed.stdout)
            if match:
                raise RecoveryExecutionError(match.group(1), (completed.stderr or completed.stdout).strip().splitlines()[-1])
            raise _journal_error(completed, code)
        lines = [line for line in completed.stdout.splitlines() if line]
        if len(lines) != 1:
            raise RecoveryExecutionError(code, "recovery database query did not return one row")
        try:
            value = json.loads(lines[0])
        except json.JSONDecodeError as error:
            raise RecoveryExecutionError(code, "recovery database row is not JSON") from error
        if not isinstance(value, dict):
            raise RecoveryExecutionError(code, "recovery database JSON is not an object")
        return value

    def query_journal(self, run_id: str) -> dict[str, Any]:
        sql = (
            "SELECT json_build_object("
            "'event_count',(SELECT count(*)::bigint FROM public.incidentseal_run_events WHERE run_id='" + run_id + "'::uuid),"
            "'last_sequence',j.sequence,'root_digest',j.link_digest,'lifecycle',j.lifecycle,'verdict',j.verdict,"
            "'terminal',j.terminal,'manifest_digest',j.manifest_digest,'approval_digest',j.approval_digest)::text "
            "FROM public.incidentseal_run_events AS j WHERE j.run_id='" + run_id + "'::uuid ORDER BY j.sequence DESC LIMIT 1;"
        )
        return self._one_json(sql)

    def query_workflow_lease(self, run_id: str, observed_at_utc: str) -> dict[str, Any]:
        sql = (
            "SELECT json_build_object("
            "'status',CASE WHEN workflow_expires_at > '" + observed_at_utc + "'::timestamptz THEN 'active' ELSE 'expired' END,"
            "'holder_id',workflow_holder_id::text,'fence_token',workflow_fence_token,"
            "'expires_at_utc',to_char(workflow_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))::text "
            "FROM public.incidentseal_recovery_fences WHERE run_id='" + run_id + "'::uuid;"
        )
        completed = _database_psql(self.docker, self.database, sql)
        if completed.returncode != 0:
            raise _journal_error(completed, "IS_RECOVERY_DATABASE")
        lines = [line for line in completed.stdout.splitlines() if line]
        if not lines:
            return {"status": "missing", "holder_id": None, "fence_token": None, "expires_at_utc": None}
        if len(lines) != 1:
            raise RecoveryExecutionError("IS_RECOVERY_DATABASE", "workflow lease query is ambiguous")
        return json.loads(lines[0])

    def inspect_runtime(self, runtime_spec: dict[str, Any]) -> dict[str, Any]:
        container_id = runtime_spec["container_id"]
        if container_id is None:
            return {
                "ownership": "exact", "process_state": "absent", "container_state": "absent",
                "process_exit_code": None, "container_exit_code": None,
            }
        completed = subprocess.run(
            [self.docker, "inspect", container_id], cwd=ROOT, text=True, encoding="utf-8",
            capture_output=True, timeout=30, check=False,
        )
        if completed.returncode != 0:
            return {
                "ownership": "exact", "process_state": "absent", "container_state": "absent",
                "process_exit_code": None, "container_exit_code": None,
            }
        values = json.loads(completed.stdout)
        if len(values) != 1:
            raise RecoveryExecutionError("IS_RECOVERY_RUNTIME", "runtime inspection is ambiguous")
        value = values[0]
        labels = value.get("Config", {}).get("Labels") or {}
        host = value.get("HostConfig", {})
        exact = all(
            (
                value.get("Id") == container_id,
                value.get("Name", "").lstrip("/") == runtime_spec["container_name"],
                value.get("Image") == runtime_spec["image_id"],
                value.get("Config", {}).get("User") == "65532:65532",
                labels.get("dev.incidentseal.contract-digest") == runtime_spec["contract_digest"],
                labels.get("dev.incidentseal.run-id") == runtime_spec["container_name"].split("-run-", 1)[-1],
                labels.get("dev.incidentseal.workflow-holder-id") == runtime_spec["workflow_holder_id"],
                labels.get("dev.incidentseal.workflow-fence-token") == str(runtime_spec["workflow_fence_token"]),
                labels.get("dev.incidentseal.recovery-surface") == "platform-validation",
                host.get("ReadonlyRootfs") is True,
                host.get("Privileged") is False,
                host.get("NetworkMode") == "none",
                "ALL" in (host.get("CapDrop") or []),
                host.get("SecurityOpt") == ["no-new-privileges"],
                not (value.get("Mounts") or []),
            )
        )
        state = value.get("State") or {}
        if state.get("Running") is True:
            runtime_state = "running"
            exit_code = None
        else:
            observed_exit = int(state.get("ExitCode", 1))
            runtime_state = "exited_zero" if observed_exit == 0 else "exited_nonzero"
            exit_code = observed_exit
        return {
            "ownership": "exact" if exact else "unowned",
            "process_state": runtime_state,
            "container_state": runtime_state,
            "process_exit_code": exit_code,
            "container_exit_code": exit_code,
        }

    def acquire_recovery_fence(
        self, run_id: str, workflow_fence_token: int, recovery_holder_id: str, expires_at_utc: str
    ) -> dict[str, Any]:
        sql = (
            "SELECT row_to_json(f)::text FROM public.incidentseal_acquire_recovery_fence("
            f"'{run_id}'::uuid,{workflow_fence_token},'{recovery_holder_id}'::uuid,'{expires_at_utc}'::timestamptz) AS f;"
        )
        value = self._one_json(sql, "IS_RECOVERY_FENCE")
        return {
            "workflow_holder_id": value["workflow_holder_id"],
            "workflow_fence_token": value["workflow_fence_token"],
            "workflow_expires_at": value["workflow_expires_at"],
            "recovery_holder_id": value["recovery_holder_id"],
            "recovery_fence_token": value["recovery_fence_token"],
            "recovery_expires_at": value["recovery_expires_at"],
        }

    def release_recovery_fence(self, run_id: str, recovery_holder_id: str, recovery_fence_token: int) -> None:
        completed = _database_psql(
            self.docker,
            self.database,
            "SELECT public.incidentseal_release_recovery_fence("
            f"'{run_id}'::uuid,'{recovery_holder_id}'::uuid,{recovery_fence_token})::text;",
        )
        if completed.returncode != 0 or completed.stdout.strip() != "true":
            raise RecoveryExecutionError("IS_RECOVERY_FENCE", "recovery fence release failed")

    def append_record(self, record: dict[str, Any]) -> dict[str, Any]:
        return append_record(self.docker, self.database, record)

    def _active_fence(self, run_id: str, holder_id: str, token: int) -> bool:
        completed = _database_psql(
            self.docker,
            self.database,
            "SELECT count(*)::text FROM public.incidentseal_recovery_fences "
            f"WHERE run_id='{run_id}'::uuid AND recovery_holder_id='{holder_id}'::uuid "
            f"AND recovery_fence_token={token} AND recovery_expires_at > CURRENT_TIMESTAMP;",
        )
        return completed.returncode == 0 and completed.stdout.strip() == "1"

    def stop_runtime(
        self, runtime_spec: dict[str, Any], recovery_holder_id: str, recovery_fence_token: int
    ) -> dict[str, Any]:
        observed = self.inspect_runtime(runtime_spec)
        run_id = runtime_spec["container_name"].split("-run-", 1)[-1]
        if (
            observed["ownership"] != "exact"
            or observed["container_state"] != "running"
            or not self._active_fence(run_id, recovery_holder_id, recovery_fence_token)
        ):
            raise RecoveryExecutionError("IS_RECOVERY_RUNTIME", "runtime stop lost exact ownership or recovery fencing")
        container_id = runtime_spec["container_id"]
        _run(self.docker, ["stop", "--time", "2", container_id], timeout=30)
        inspected = json.loads(_run(self.docker, ["inspect", container_id]).stdout)[0]
        exit_code = int(inspected.get("State", {}).get("ExitCode", -1))
        _run(self.docker, ["rm", container_id])
        return {
            "schema_version": "incidentseal-recovery-process-receipt/v1",
            "container_id": container_id,
            "container_name": runtime_spec["container_name"],
            "workflow_fence_token": runtime_spec["workflow_fence_token"],
            "recovery_fence_token": recovery_fence_token,
            "exit_code": exit_code,
            "removed": True,
        }

    def replay_step(self, plan: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        expected = b"incidentseal-recovery-replay-v1\n"
        completed = subprocess.run(
            [
                self.docker, "run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532",
                "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                self.python_image_id, "-c", "print('incidentseal-recovery-replay-v1')",
            ],
            cwd=ROOT, capture_output=True, timeout=60, check=False,
        )
        if completed.returncode != 0 or completed.stdout != expected or completed.stderr:
            raise RecoveryExecutionError("IS_RECOVERY_REPLAY", "fixed idempotent replay container failed")
        artifacts = self.state_root / "artifacts"
        artifacts.mkdir(exist_ok=True)
        artifact = artifacts / f"{plan['run_id']}.txt"
        if artifact.exists() and artifact.read_bytes() != expected:
            raise RecoveryExecutionError("IS_RECOVERY_EFFECTS_CONFLICT", "replay artifact conflicts")
        if not artifact.exists():
            artifact.write_bytes(expected)
        input_digest = _digest(canonical_bytes({"run_id": plan["run_id"], "step": plan["boundary"]["step_id"]}))
        result_digest = _digest(expected)
        existing = _database_psql(
            self.docker, self.database,
            "SELECT input_digest || '|' || result_digest FROM public.verification_results "
            f"WHERE run_id='recovery-{plan['run_id']}' AND runner='python';",
        )
        if existing.returncode != 0:
            raise _journal_error(existing, "IS_RECOVERY_DATABASE")
        if existing.stdout.strip() and existing.stdout.strip() != f"{input_digest}|{result_digest}":
            raise RecoveryExecutionError("IS_RECOVERY_EFFECTS_CONFLICT", "replay database result conflicts")
        if not existing.stdout.strip():
            inserted = _database_psql(
                self.docker, self.database,
                "INSERT INTO public.verification_results(run_id,runner,input_digest,result_digest) VALUES ("
                f"'recovery-{plan['run_id']}','python','{input_digest}','{result_digest}');",
            )
            if inserted.returncode != 0:
                raise _journal_error(inserted, "IS_RECOVERY_DATABASE")
        plan["boundary"]["phase"] = "result_committed"
        plan["effects"].update({"artifact": "matching", "database": "matching", "receipt": "absent"})
        return {
            "schema_version": "incidentseal-recovery-replay-receipt/v1",
            "decision_digest": decision["decision_digest"],
            "artifact_digest": result_digest,
            "database_result": "matching",
            "container_network": "none",
            "container_removed": True,
        }

    def expire_recovery_fence_for_probe(self, run_id: str) -> None:
        completed = _database_psql(
            self.docker, self.database,
            "UPDATE public.incidentseal_recovery_fences SET recovery_expires_at=CURRENT_TIMESTAMP - interval '1 second' "
            f"WHERE run_id='{run_id}'::uuid;",
        )
        if completed.returncode != 0:
            raise _journal_error(completed, "IS_RECOVERY_DATABASE")


def _event(run_id: str, sequence: int, timestamp: str, event_type: str, lifecycle: str, manifest: str) -> dict[str, Any]:
    return {
        "schema_version": "incidentseal-run-event/v1",
        "event_id": _deterministic_uuid(f"{run_id}:seed:{sequence}"),
        "run_id": run_id,
        "sequence": sequence,
        "occurred_at_utc": timestamp,
        "event_type": event_type,
        "lifecycle": lifecycle,
        "verdict": None,
        "terminal": False,
        "manifest_digest": manifest,
        "approval_digest": manifest,
        "payload": {"kind": "recovery.probe.seed", "sequence": sequence},
        "error": None,
    }


def _seed_run(
    backend: DockerRecoveryBackend,
    run_id: str,
    workflow_holder_id: str,
    workflow_fence_token: int,
    *,
    lease_active: bool,
    manifest: str,
) -> None:
    timestamp = _now()
    first = _record_for_event(_event(run_id, 0, timestamp, "run.queued", "queued", manifest), GENESIS)
    second = _record_for_event(_event(run_id, 1, _shift(timestamp, 1), "run.started", "running", manifest), first["link_digest"])
    backend.append_record(first)
    backend.append_record(second)
    interval = "1 minute" if lease_active else "-1 minute"
    completed = _database_psql(
        backend.docker,
        backend.database,
        "INSERT INTO public.incidentseal_recovery_fences("
        "run_id,workflow_holder_id,workflow_fence_token,workflow_expires_at) VALUES ("
        f"'{run_id}'::uuid,'{workflow_holder_id}'::uuid,{workflow_fence_token},CURRENT_TIMESTAMP + interval '{interval}');",
    )
    if completed.returncode != 0:
        raise _journal_error(completed, "IS_RECOVERY_DATABASE")


def _spawn_runtime(
    docker: str,
    *,
    name: str,
    run_id: str,
    image_id: str,
    contract_digest: str,
    workflow_holder_id: str,
    workflow_fence_token: int,
    running: bool,
    exact: bool,
) -> str:
    labels = [
        "--label", f"dev.incidentseal.contract-digest={contract_digest}",
        "--label", f"dev.incidentseal.run-id={run_id}",
        "--label", f"dev.incidentseal.workflow-holder-id={workflow_holder_id}",
        "--label", f"dev.incidentseal.workflow-fence-token={workflow_fence_token if exact else workflow_fence_token + 1000}",
        "--label", "dev.incidentseal.recovery-surface=platform-validation",
    ]
    code = "import time;time.sleep(120)" if running else "import sys;sys.exit(42)"
    completed = _run(
        docker,
        [
            "run", "-d", "--name", name, "--network", "none", "--read-only", "--user", "65532:65532",
            "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            *labels, image_id, "-c", code,
        ],
        timeout=60,
    )
    container_id = completed.stdout.strip()
    if not running:
        wait = subprocess.run([docker, "wait", container_id], cwd=ROOT, text=True, capture_output=True, timeout=30, check=False)
        if wait.returncode != 0 or wait.stdout.strip() != "42":
            raise TopologyError("IS_RECOVERY_PROBE", "failed runtime did not retain exit 42")
    return container_id


def _plan(
    case_id: str,
    *,
    run_id: str,
    manifest: str,
    authority_status: str = "MATCH",
    observed_authority: str | None = None,
    request: str = "reconcile",
    interruption: str = "host_crash",
    phase: str = "dispatched",
    replay_policy: str = "idempotent",
    effects: dict[str, str] | None = None,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "incidentseal-recovery-plan/v1",
        "run_id": run_id,
        "request": request,
        "interruption": interruption,
        "authority": {
            "expected_manifest_digest": manifest,
            "approval_status": authority_status,
            "observed_approval_digest": manifest if observed_authority is None and authority_status == "MATCH" else observed_authority,
        },
        "boundary": {"step_id": f"recovery.{case_id}", "attempt": 1, "phase": phase, "replay_policy": replay_policy},
        "effects": effects or {"artifact": "absent", "database": "absent", "receipt": "absent"},
        "runtime": runtime,
    }


def recovery_probe() -> dict[str, Any]:
    """Exercise real fencing, stop, append, resume, replay, and teardown in disposable custody."""

    static = validate_platform_topology()
    implementation_lock_digest = validate_recovery_implementation_lock()
    validate_journal_lock()
    docker = _docker_executable()
    volume_lock, protected = _load_retained_volume_lock(docker)
    protected_before = _volume_snapshot(docker, protected)
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    disposable = volume_lock["disposable_project"]
    project = disposable["name"]
    volume = disposable["volume"]
    network = f"{project}_data"
    database = f"{project}-database-1"
    migration = f"{project}-migration-recovery"
    manifest = "sha256:0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45"
    checks: list[dict[str, Any]] = []
    results: dict[str, Any] = {}

    def check(check_id: str, passed: bool, observed: Any) -> None:
        checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})

    before_volumes = _volume_names(docker)
    stale_containers = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
    stale_network = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
    if stale_containers or stale_network or volume in before_volumes:
        raise TopologyError("IS_RECOVERY_STALE", "disposable recovery resources already exist")

    cleanup_exit: int | None = None
    state_custody: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-probe-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        state_custody = custody
        if ROOT == custody or ROOT in custody.parents or any(part.casefold() == "onedrive" for part in custody.parts):
            raise TopologyError("IS_RECOVERY_CUSTODY", "recovery probe custody overlaps a forbidden root")
        for name in ("input", "python-output", "node-output", "recovery-state"):
            (custody / name).mkdir()
        (custody / "input" / "request.json").write_text("{}\n", encoding="utf-8")
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, _, _ = _compose_env(contract, identities, custody)
        env["INCIDENTSEAL_PROJECT_NAME"] = project
        env["INCIDENTSEAL_RUN_ID"] = "isrun-4444444444444444"
        base = _compose_args(env_file)
        backend: DockerRecoveryBackend | None = None
        try:
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            _wait_healthy(docker, database)
            database_inspection = _inspect_container(docker, database, identities["database"], "70:70", network)
            _run(docker, [*base, "run", "--name", migration, "--no-deps", "migration"], env=env)
            migration_inspection = _inspect_container(docker, migration, identities["migration"], "70:70", network)
            _run(docker, ["rm", "-f", migration])
            backend = DockerRecoveryBackend(docker, database, identities["python-runner"], custody / "recovery-state")
            check("fresh-disposable-bootstrap", volume in _volume_names(docker), {"healthy": True, "volume": volume})

            def setup(
                case_id: str,
                index: int,
                *,
                lease_active: bool = False,
                running: bool | None = None,
                exact: bool = True,
                **plan_options: Any,
            ) -> tuple[dict[str, Any], str]:
                run_id = _deterministic_uuid(f"incidentseal-recovery-probe:{case_id}")
                workflow_holder = _deterministic_uuid(f"incidentseal-workflow-holder:{case_id}")
                workflow_token = 100 + index
                _seed_run(
                    backend, run_id, workflow_holder, workflow_token,
                    lease_active=lease_active, manifest=manifest,
                )
                container_name = f"{project}-run-{run_id}"
                container_id = None
                if running is not None:
                    container_id = _spawn_runtime(
                        docker,
                        name=container_name,
                        run_id=run_id,
                        image_id=identities["python-runner"],
                        contract_digest=_sha256_file(CONTRACT_PATH),
                        workflow_holder_id=workflow_holder,
                        workflow_fence_token=workflow_token,
                        running=running,
                        exact=exact,
                    )
                runtime = {
                    "container_id": container_id,
                    "container_name": container_name,
                    "image_id": identities["python-runner"],
                    "contract_digest": _sha256_file(CONTRACT_PATH),
                    "workflow_holder_id": workflow_holder,
                    "workflow_fence_token": workflow_token,
                }
                return _plan(case_id, run_id=run_id, manifest=manifest, runtime=runtime, **plan_options), run_id

            # An active workflow owner must not be fenced, stopped, or journaled.
            active_plan, active_run = setup(
                "active-owner", 1, lease_active=True, running=True,
                effects={"artifact": "unknown", "database": "unknown", "receipt": "unknown"},
            )
            active = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:active")
            ).reconcile(active_plan)
            active_runtime = backend.inspect_runtime(active_plan["runtime"])
            active_journal = backend.query_journal(active_run)
            check(
                "active-owner-defers-without-mutation",
                active["verification_verdict"] == "INCONCLUSIVE"
                and not active["fence_acquired"]
                and active_runtime["container_state"] == "running"
                and active_journal["event_count"] == 2,
                {"decision": active["decisions"][0]["reason_code"], "event_count": active_journal["event_count"]},
            )
            _run(docker, ["rm", "-f", active_plan["runtime"]["container_id"]])

            # A lookalike runtime never grants stop authority.
            unowned_plan, unowned_run = setup(
                "unowned-orphan", 2, running=True, exact=False,
                interruption="orphan_detected",
                effects={"artifact": "unknown", "database": "unknown", "receipt": "unknown"},
            )
            unowned = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:unowned")
            ).reconcile(unowned_plan)
            unowned_runtime = backend.inspect_runtime(unowned_plan["runtime"])
            unowned_journal = backend.query_journal(unowned_run)
            check(
                "unowned-orphan-defers-without-mutation",
                unowned["verification_verdict"] == "INCONCLUSIVE"
                and not unowned["fence_acquired"]
                and unowned_runtime["container_state"] == "running"
                and unowned_journal["event_count"] == 2,
                {"decision": unowned["decisions"][0]["reason_code"], "event_count": unowned_journal["event_count"]},
            )
            _run(docker, ["rm", "-f", unowned_plan["runtime"]["container_id"]])

            # Exactly owned orphan: evidence, fenced stop, reobservation, one idempotent replay.
            orphan_plan, orphan_run = setup(
                "owned-orphan", 3, running=True, interruption="orphan_detected",
                phase="before_dispatch", effects={"artifact": "absent", "database": "absent", "receipt": "absent"},
            )
            orphan = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:orphan")
            ).reconcile(orphan_plan)
            orphan_journal = backend.query_journal(orphan_run)
            replay_row = _database_psql(
                docker, database,
                f"SELECT count(*)::text FROM public.verification_results WHERE run_id='recovery-{orphan_run}' AND runner='python';",
            )
            check(
                "owned-orphan-stop-reobserve-replay",
                [item["disposition"] for item in orphan["decisions"]] == ["stop_then_reconcile", "resume"]
                and orphan_journal["event_count"] == 4
                and orphan_journal["lifecycle"] == "running"
                and replay_row.stdout.strip() == "1"
                and backend.inspect_runtime(orphan_plan["runtime"])["container_state"] == "absent",
                {"decisions": [item["reason_code"] for item in orphan["decisions"]], "event_count": orphan_journal["event_count"]},
            )

            # Running cancellation: fenced stop then distinct cancelled terminal with null run verdict.
            cancel_plan, cancel_run = setup(
                "running-cancel", 4, running=True, request="cancel", interruption="operator_cancel",
                effects={"artifact": "absent", "database": "absent", "receipt": "absent"},
            )
            cancelled = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:cancel")
            ).reconcile(cancel_plan)
            cancelled_stream = _run_stream_cli(cancel_run)
            check(
                "running-cancellation-terminal",
                [item["disposition"] for item in cancelled["decisions"]] == ["stop_then_reconcile", "cancel"]
                and cancelled_stream.returncode == 20
                and cancelled_stream.stdout.count(b"\n") == 5
                and not cancelled_stream.stderr,
                {"exit_code": cancelled_stream.returncode, "lines": cancelled_stream.stdout.count(b"\n")},
            )

            # Retained nonzero process exit becomes failed lifecycle, never a run verdict.
            failure_plan, failure_run = setup(
                "process-failure", 5, running=False, interruption="process_exit",
                effects={"artifact": "absent", "database": "absent", "receipt": "absent"},
            )
            failed = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:failure")
            ).reconcile(failure_plan)
            failed_stream = _run_stream_cli(failure_run)
            check(
                "nonzero-process-failure-terminal",
                failed["decisions"][0]["disposition"] == "fail"
                and failed["decisions"][0]["verification_verdict"] == "PASS"
                and failed_stream.returncode == 21
                and failed_stream.stdout.count(b"\n") == 4,
                {"exit_code": failed_stream.returncode, "reason": failed["decisions"][0]["reason_code"]},
            )

            # Authority drift terminalizes stale while preserving the original journal authority.
            stale_plan, stale_run = setup(
                "authority-stale", 6,
                authority_status="MISMATCH", observed_authority="sha256:" + "1" * 64,
                effects={"artifact": "absent", "database": "absent", "receipt": "absent"},
            )
            stale = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:stale")
            ).reconcile(stale_plan)
            stale_stream = _run_stream_cli(stale_run)
            check(
                "authority-drift-stale-terminal",
                stale["decisions"][0]["disposition"] == "stale"
                and stale_stream.returncode == 22
                and stale_stream.stdout.count(b"\n") == 4,
                {"exit_code": stale_stream.returncode, "reason": stale["decisions"][0]["reason_code"]},
            )

            # Conflicting and ambiguous effects remain different evidence outcomes.
            conflict_plan, conflict_run = setup(
                "conflicting-effects", 7, phase="result_committed",
                effects={"artifact": "matching", "database": "conflicting", "receipt": "absent"},
            )
            conflict = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:conflict")
            ).reconcile(conflict_plan)
            conflict_stream = _run_stream_cli(conflict_run)
            ambiguous_plan, ambiguous_run = setup(
                "ambiguous-effects", 8,
                effects={"artifact": "unknown", "database": "absent", "receipt": "absent"},
            )
            ambiguous = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:ambiguous")
            ).reconcile(ambiguous_plan)
            ambiguous_stream = _run_stream_cli(ambiguous_run)
            check(
                "effect-state-separation",
                conflict["verification_verdict"] == "FAIL"
                and conflict_stream.returncode == 21
                and ambiguous["verification_verdict"] == "INCONCLUSIVE"
                and ambiguous_stream.returncode == 11
                and ambiguous_stream.stdout.count(b"\n") == 3,
                {"conflict_exit": conflict_stream.returncode, "ambiguous_exit": ambiguous_stream.returncode},
            )

            # Crash after evidence append: new holder reacquires an expired recovery fence and completes exactly once.
            crash_plan, crash_run = setup(
                "crash-after-evidence", 9, running=False, interruption="process_exit",
                effects={"artifact": "absent", "database": "absent", "receipt": "absent"},
            )
            interrupted = False
            try:
                RecoveryExecutor(
                    backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:crash-one")
                ).reconcile(crash_plan, interrupt_after_evidence=True)
            except RecoveryInterrupted:
                interrupted = True
            after_interrupt = backend.query_journal(crash_run)
            backend.expire_recovery_fence_for_probe(crash_run)
            resumed = RecoveryExecutor(
                backend, custody / "recovery-state", _deterministic_uuid("recovery-holder:crash-two")
            ).reconcile(crash_plan)
            resumed_stream = _run_stream_cli(crash_run)
            check(
                "durable-pending-resume",
                interrupted
                and after_interrupt["event_count"] == 3
                and resumed_stream.returncode == 21
                and resumed_stream.stdout.count(b"\n") == 4
                and not (custody / "recovery-state" / f"{crash_run}.pending.json").exists(),
                {"before_resume_events": after_interrupt["event_count"], "after_resume_lines": resumed_stream.stdout.count(b"\n")},
            )

            # A second recovery holder cannot acquire an unexpired recovery fence.
            fence_plan, fence_run = setup("fence-race", 10)
            holder_one = _deterministic_uuid("recovery-holder:fence-one")
            holder_two = _deterministic_uuid("recovery-holder:fence-two")
            observed = RecoveryExecutor(backend, custody / "recovery-state", holder_one)._observe(fence_plan)
            acquired = backend.acquire_recovery_fence(
                fence_run, observed["lease"]["fence_token"], holder_one, _shift(_now(), 120)
            )
            second_code = None
            try:
                backend.acquire_recovery_fence(
                    fence_run, observed["lease"]["fence_token"], holder_two, _shift(_now(), 120)
                )
            except RecoveryError as error:
                second_code = error.code
            backend.release_recovery_fence(fence_run, holder_one, acquired["recovery_fence_token"])
            check(
                "concurrent-recoverer-fenced",
                second_code == "IS_RECOVERY_ACTIVE_OWNER",
                {"second_holder_error": second_code, "recovery_fence_token": acquired["recovery_fence_token"]},
            )

            runner_fence_read = _database_psql(
                docker, database, "SELECT count(*) FROM public.incidentseal_recovery_fences;", user="incidentseal_runner"
            )
            check(
                "runner-recovery-state-denied",
                runner_fence_read.returncode != 0 and "permission denied" in (runner_fence_read.stderr + runner_fence_read.stdout).lower(),
                {"exit_code": runner_fence_read.returncode},
            )

            # PostgreSQL restart must retain completed recovery history and exact lifecycle exits.
            _run(docker, ["restart", database])
            _wait_healthy(docker, database)
            restart_cancel = _run_stream_cli(cancel_run)
            restart_failed = _run_stream_cli(failure_run)
            restart_stale = _run_stream_cli(stale_run)
            check(
                "restart-persistence",
                (restart_cancel.returncode, restart_failed.returncode, restart_stale.returncode) == (20, 21, 22)
                and restart_cancel.stdout == cancelled_stream.stdout
                and restart_failed.stdout == failed_stream.stdout
                and restart_stale.stdout == stale_stream.stdout,
                {"exits": [restart_cancel.returncode, restart_failed.returncode, restart_stale.returncode]},
            )

            all_events = _database_psql(
                docker, database,
                "SELECT count(*)::text FROM public.incidentseal_run_events WHERE verdict IS NOT NULL AND lifecycle <> 'completed';",
            )
            check(
                "recovery-never-fabricates-run-verdict",
                all_events.returncode == 0 and all_events.stdout.strip() == "0",
                {"noncompleted_verdict_rows": all_events.stdout.strip()},
            )
            results = {
                "active_owner": active_run,
                "unowned_orphan": unowned_run,
                "owned_orphan": orphan_run,
                "cancelled": cancel_run,
                "failed": failure_run,
                "stale": stale_run,
                "conflicting": conflict_run,
                "ambiguous": ambiguous_run,
                "resumed": crash_run,
                "database_inspection": database_inspection,
                "migration_inspection": migration_inspection,
                "archived_recovery_decisions": len(list((custody / "recovery-state" / "history").glob("*.json"))),
            }
        finally:
            recovery_containers = subprocess.run(
                [docker, "ps", "-aq", "--filter", "label=dev.incidentseal.recovery-surface=platform-validation"],
                cwd=ROOT, text=True, capture_output=True, timeout=30, check=False,
            )
            for container_id in recovery_containers.stdout.splitlines():
                subprocess.run([docker, "rm", "-f", container_id], cwd=ROOT, capture_output=True, check=False)
            subprocess.run([docker, "rm", "-f", migration], cwd=ROOT, capture_output=True, check=False)
            cleanup = subprocess.run(
                [docker, *base, "down", "--volumes", "--remove-orphans"],
                cwd=ROOT, env=env, text=True, encoding="utf-8", capture_output=True, timeout=180, check=False,
            )
            cleanup_exit = cleanup.returncode

    if state_custody is None or state_custody.exists():
        raise TopologyError("IS_RECOVERY_CUSTODY", "temporary recovery state custody remained")
    after_volumes = _volume_names(docker)
    protected_after = _volume_snapshot(docker, protected)
    containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
    network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
    custody_ok = protected_before == protected_after and protected.issubset(after_volumes)
    teardown_ok = cleanup_exit == 0 and not containers_left and not network_left and volume not in after_volumes
    check("protected-volume-identities-unchanged", custody_ok, {"before": protected_before, "after": protected_after})
    check(
        "disposable-teardown",
        teardown_ok,
        {"cleanup_exit_code": cleanup_exit, "containers": containers_left, "network": network_left, "volume_exists": volume in after_volumes},
    )
    if not custody_ok or not teardown_ok:
        raise TopologyError("IS_RECOVERY_TEARDOWN", "recovery probe teardown or protected-volume identity differs")
    verdict = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    return {
        "schema_version": "incidentseal-recovery-probe/v1",
        "verdict": verdict,
        "mode": "platform-validation",
        "claim_scope": "fixed-synthetic-host-recovery-only",
        "project_name": project,
        "contract_digest": _sha256_file(CONTRACT_PATH),
        "recovery_implementation_lock_digest": implementation_lock_digest,
        "images": image_receipts,
        "checks": checks,
        "results": results,
        "protected_volumes": sorted(protected),
        "disposable_volume_removed": True,
        "containers_removed": True,
        "network_removed": True,
        "state_custody_removed": True,
        "approval_accessed": False,
        "workflow_executed": False,
        "runtime_started": True,
        "static_validation": static.data,
    }
