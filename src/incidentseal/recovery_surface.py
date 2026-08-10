"""Host-only fenced recovery execution against the frozen recovery contract."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Protocol
import uuid

from .journal import GENESIS, JournalError
from .journal_surface import _record_for_event
from .manifest import canonical_bytes, strict_load_bytes
from .recovery import RecoveryError, decide_recovery, validate_decision, validate_observation
from .topology import ROOT, TopologyError


PLAN_FIELDS = {
    "schema_version", "run_id", "request", "interruption", "authority", "boundary", "effects", "runtime"
}
RUNTIME_SPEC_FIELDS = {
    "container_id", "container_name", "image_id", "contract_digest", "workflow_holder_id", "workflow_fence_token"
}
PENDING_FIELDS = {
    "schema_version", "run_id", "recovery_holder_id", "recovery_fence_token", "observation", "decision",
    "evidence_record", "terminal_record", "evidence_appended", "terminal_appended", "replay_completed",
    "process_stopped", "append_results", "replay_receipt", "process_receipt", "status"
}


class RecoveryExecutionError(RecoveryError):
    """Stable rejection from the host recovery executor."""


class RecoveryInterrupted(RuntimeError):
    """Intentional probe interruption after a durable recovery boundary."""


class RecoveryBackend(Protocol):
    def query_journal(self, run_id: str) -> dict[str, Any]: ...
    def query_workflow_lease(self, run_id: str, observed_at_utc: str) -> dict[str, Any]: ...
    def inspect_runtime(self, runtime_spec: dict[str, Any]) -> dict[str, Any]: ...
    def acquire_recovery_fence(
        self, run_id: str, workflow_fence_token: int, recovery_holder_id: str, expires_at_utc: str
    ) -> dict[str, Any]: ...
    def release_recovery_fence(self, run_id: str, recovery_holder_id: str, recovery_fence_token: int) -> None: ...
    def append_record(self, record: dict[str, Any]) -> dict[str, Any]: ...
    def stop_runtime(
        self, runtime_spec: dict[str, Any], recovery_holder_id: str, recovery_fence_token: int
    ) -> dict[str, Any]: ...
    def replay_step(self, plan: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]: ...


def _reject(code: str, message: str) -> None:
    raise RecoveryExecutionError(code, message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_RECOVERY_IMPLEMENTATION", f"{label} fields differ")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plus_second(value: str) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (parsed + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deterministic_uuid(seed: str) -> str:
    raw = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def validate_plan(value: Any) -> dict[str, Any]:
    plan = _exact(value, PLAN_FIELDS, "recovery plan")
    if plan["schema_version"] != "incidentseal-recovery-plan/v1":
        _reject("IS_RECOVERY_IMPLEMENTATION", "recovery plan version differs")
    runtime = _exact(plan["runtime"], RUNTIME_SPEC_FIELDS, "recovery runtime specification")
    if not isinstance(runtime["workflow_fence_token"], int) or isinstance(runtime["workflow_fence_token"], bool):
        _reject("IS_RECOVERY_IMPLEMENTATION", "runtime workflow fence token is invalid")
    if runtime["container_id"] is not None and not isinstance(runtime["container_id"], str):
        _reject("IS_RECOVERY_IMPLEMENTATION", "runtime container ID is invalid")
    probe_observation = {
        "schema_version": "incidentseal-recovery-observation/v1",
        "reconciliation_id": str(uuid.uuid4()),
        "run_id": plan["run_id"],
        "observed_at_utc": _utc_now(),
        "request": plan["request"],
        "interruption": plan["interruption"],
        "authority": deepcopy(plan["authority"]),
        "journal": {
            "event_count": 1, "last_sequence": 0, "root_digest": GENESIS, "lifecycle": "running",
            "verdict": None, "terminal": False,
            "manifest_digest": plan["authority"]["expected_manifest_digest"],
            "approval_digest": plan["authority"]["expected_manifest_digest"],
        },
        "boundary": deepcopy(plan["boundary"]),
        "lease": {
            "status": "expired", "holder_id": runtime["workflow_holder_id"],
            "fence_token": runtime["workflow_fence_token"], "expires_at_utc": "2026-01-01T00:00:00Z",
        },
        "runtime": {
            "ownership": "exact", "process_state": "absent", "container_state": "absent",
            "process_exit_code": None, "container_exit_code": None,
        },
        "effects": deepcopy(plan["effects"]),
    }
    validate_observation(probe_observation)
    return plan


class PendingStore:
    """Atomic non-repository custody for an interrupted recovery decision."""

    def __init__(self, root: Path) -> None:
        candidate = root.expanduser().resolve(strict=False)
        repository = ROOT.resolve(strict=True)
        if candidate == repository or repository in candidate.parents or any(part.casefold() == "onedrive" for part in candidate.parts):
            _reject("IS_RECOVERY_CUSTODY", "recovery state overlaps the repository or OneDrive")
        candidate.mkdir(parents=True, exist_ok=True)
        if candidate.is_symlink():
            _reject("IS_RECOVERY_CUSTODY", "recovery state root is a symbolic link")
        self.root = candidate.resolve(strict=True)

    def _active_path(self, run_id: str) -> Path:
        return self.root / f"{run_id}.pending.json"

    def load(self, run_id: str) -> dict[str, Any] | None:
        path = self._active_path(run_id)
        if not path.is_file():
            return None
        try:
            value = strict_load_bytes(path.read_bytes())
        except (OSError, ValueError) as error:
            _reject("IS_RECOVERY_CUSTODY", "pending recovery state is unreadable")
        pending = _exact(value, PENDING_FIELDS, "pending recovery state")
        if pending["schema_version"] != "incidentseal-recovery-pending/v1" or pending["run_id"] != run_id:
            _reject("IS_RECOVERY_CUSTODY", "pending recovery identity differs")
        validate_decision(pending["decision"], pending["observation"])
        return pending

    def save(self, pending_value: dict[str, Any]) -> None:
        pending = _exact(pending_value, PENDING_FIELDS, "pending recovery state")
        run_id = pending["run_id"]
        raw = canonical_bytes(pending)
        target = self._active_path(run_id)
        handle, temporary_name = tempfile.mkstemp(prefix=f".{run_id}.", suffix=".tmp", dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()

    def archive(self, pending: dict[str, Any]) -> Path:
        history = self.root / "history"
        history.mkdir(exist_ok=True)
        target = history / f"{pending['decision']['decision_digest'].split(':', 1)[1]}.json"
        raw = canonical_bytes(pending)
        if target.exists() and target.read_bytes() != raw:
            _reject("IS_RECOVERY_CUSTODY", "completed recovery history conflicts")
        if not target.exists():
            target.write_bytes(raw)
        active = self._active_path(pending["run_id"])
        if active.exists():
            active.unlink()
        return target


def _evidence_event(observation: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    journal = observation["journal"]
    return {
        "schema_version": "incidentseal-run-event/v1",
        "event_id": _deterministic_uuid(decision["decision_digest"] + ":evidence"),
        "run_id": observation["run_id"],
        "sequence": journal["event_count"],
        "occurred_at_utc": observation["observed_at_utc"],
        "event_type": "evidence.recorded",
        "lifecycle": "running",
        "verdict": None,
        "terminal": False,
        "manifest_digest": journal["manifest_digest"],
        "approval_digest": journal["approval_digest"],
        "payload": {
            "kind": "recovery.decision",
            "observation_digest": decision["observation_digest"],
            "decision_digest": decision["decision_digest"],
            "verification_verdict": decision["verification_verdict"],
            "disposition": decision["disposition"],
            "reason_code": decision["reason_code"],
            "process_action": decision["process_action"],
            "replay_step": decision["replay_step"],
        },
        "error": None,
    }


def _terminal_event(observation: dict[str, Any], decision: dict[str, Any], sequence: int) -> dict[str, Any] | None:
    append = decision["append"]
    event_type = append["terminal_event_type"]
    lifecycle = append["terminal_lifecycle"]
    if event_type is None:
        return None
    journal = observation["journal"]
    if lifecycle == "stale":
        payload = {
            "expected_authority_digest": observation["authority"]["expected_manifest_digest"],
            "observed_authority_digest": observation["authority"]["observed_approval_digest"],
            "reason": decision["reason_code"],
        }
    else:
        payload = {"recovery_decision_digest": decision["decision_digest"], "reason": decision["reason_code"]}
    error = None
    if lifecycle == "failed":
        error = {"code": decision["reason_code"], "message": "Recovery classified the interrupted run as failed.", "retriable": False}
    return {
        "schema_version": "incidentseal-run-event/v1",
        "event_id": _deterministic_uuid(decision["decision_digest"] + ":terminal"),
        "run_id": observation["run_id"],
        "sequence": sequence,
        "occurred_at_utc": _plus_second(observation["observed_at_utc"]),
        "event_type": event_type,
        "lifecycle": lifecycle,
        "verdict": None,
        "terminal": True,
        "manifest_digest": journal["manifest_digest"],
        "approval_digest": journal["approval_digest"],
        "payload": payload,
        "error": error,
    }


def build_pending(
    observation_value: dict[str, Any], decision_value: dict[str, Any], holder_id: str, recovery_fence_token: int
) -> dict[str, Any]:
    observation = validate_observation(observation_value)
    decision = validate_decision(decision_value, observation)
    evidence_record = None
    terminal_record = None
    previous = observation["journal"]["root_digest"]
    sequence = observation["journal"]["event_count"]
    if decision["append"]["evidence_event_type"] is not None:
        evidence_record = _record_for_event(_evidence_event(observation, decision), previous)
        previous = evidence_record["link_digest"]
        sequence += 1
    terminal = _terminal_event(observation, decision, sequence)
    if terminal is not None:
        terminal_record = _record_for_event(terminal, previous)
    return {
        "schema_version": "incidentseal-recovery-pending/v1",
        "run_id": observation["run_id"],
        "recovery_holder_id": holder_id,
        "recovery_fence_token": recovery_fence_token,
        "observation": observation,
        "decision": decision,
        "evidence_record": evidence_record,
        "terminal_record": terminal_record,
        "evidence_appended": False,
        "terminal_appended": False,
        "replay_completed": False,
        "process_stopped": False,
        "append_results": [],
        "replay_receipt": None,
        "process_receipt": None,
        "status": "planned",
    }


class RecoveryExecutor:
    """Serialize, execute, and durably resume one frozen recovery decision at a time."""

    def __init__(
        self,
        backend: RecoveryBackend,
        state_root: Path,
        holder_id: str,
        *,
        now: Any = _utc_now,
    ) -> None:
        self.backend = backend
        self.store = PendingStore(state_root)
        self.holder_id = str(uuid.UUID(holder_id))
        self.now = now

    def _observe(
        self,
        plan: dict[str, Any],
        *,
        reconciliation_id: str | None = None,
        observed_at_utc: str | None = None,
    ) -> dict[str, Any]:
        timestamp = observed_at_utc or self.now()
        observation = {
            "schema_version": "incidentseal-recovery-observation/v1",
            "reconciliation_id": reconciliation_id or str(uuid.uuid4()),
            "run_id": plan["run_id"],
            "observed_at_utc": timestamp,
            "request": plan["request"],
            "interruption": plan["interruption"],
            "authority": deepcopy(plan["authority"]),
            "journal": self.backend.query_journal(plan["run_id"]),
            "boundary": deepcopy(plan["boundary"]),
            "lease": self.backend.query_workflow_lease(plan["run_id"], timestamp),
            "runtime": self.backend.inspect_runtime(plan["runtime"]),
            "effects": deepcopy(plan["effects"]),
        }
        return validate_observation(observation)

    @staticmethod
    def _needs_fence(decision: dict[str, Any]) -> bool:
        return any(
            (
                decision["process_action"] != "none",
                decision["replay_step"],
                decision["append"]["evidence_event_type"] is not None,
                decision["append"]["terminal_event_type"] is not None,
            )
        )

    def _acquire(self, observation: dict[str, Any]) -> dict[str, Any]:
        expires = (datetime.strptime(self.now(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.backend.acquire_recovery_fence(
            observation["run_id"], observation["lease"]["fence_token"], self.holder_id, expires
        )

    def _execute_pending(
        self,
        plan: dict[str, Any],
        pending: dict[str, Any],
        *,
        interrupt_after_evidence: bool,
    ) -> tuple[dict[str, Any], bool]:
        decision = pending["decision"]
        if decision["replay_step"] and not pending["replay_completed"]:
            pending["replay_receipt"] = self.backend.replay_step(plan, decision)
            pending["replay_completed"] = True
            pending["status"] = "replay-completed"
            self.store.save(pending)
        if pending["evidence_record"] is not None:
            outcome = self.backend.append_record(pending["evidence_record"])
            if outcome.get("disposition") not in {"inserted", "replayed"}:
                _reject("IS_RECOVERY_APPEND", "recovery evidence append disposition differs")
            if not pending["evidence_appended"]:
                pending["append_results"].append(outcome)
            pending["evidence_appended"] = True
            pending["status"] = "evidence-appended"
            self.store.save(pending)
            if interrupt_after_evidence:
                raise RecoveryInterrupted("intentional interruption after recovery evidence append")
        if decision["process_action"] == "stop_owned_and_wait" and not pending["process_stopped"]:
            pending["process_receipt"] = self.backend.stop_runtime(
                plan["runtime"], pending["recovery_holder_id"], pending["recovery_fence_token"]
            )
            pending["process_stopped"] = True
            pending["status"] = "reobserve-required"
            self.store.save(pending)
            return pending, True
        if pending["terminal_record"] is not None:
            outcome = self.backend.append_record(pending["terminal_record"])
            if outcome.get("disposition") not in {"inserted", "replayed"}:
                _reject("IS_RECOVERY_APPEND", "recovery terminal append disposition differs")
            if not pending["terminal_appended"]:
                pending["append_results"].append(outcome)
            pending["terminal_appended"] = True
            pending["status"] = "terminal-appended"
            self.store.save(pending)
        pending["status"] = "completed"
        self.store.save(pending)
        return pending, False

    def reconcile(
        self,
        plan_value: dict[str, Any],
        *,
        interrupt_after_evidence: bool = False,
    ) -> dict[str, Any]:
        plan = validate_plan(deepcopy(plan_value))
        decisions: list[dict[str, Any]] = []
        histories: list[str] = []
        pending = self.store.load(plan["run_id"])
        fence: dict[str, Any] | None = None
        try:
            if pending is not None:
                fence = self._acquire(pending["observation"])
                pending["recovery_holder_id"] = self.holder_id
                pending["recovery_fence_token"] = fence["recovery_fence_token"]
                self.store.save(pending)
            else:
                observation = self._observe(plan)
                decision = decide_recovery(observation)
                decisions.append(decision)
                if not self._needs_fence(decision):
                    return {
                        "schema_version": "incidentseal-recovery-execution/v1",
                        "run_id": plan["run_id"],
                        "verification_verdict": decision["verification_verdict"],
                        "decisions": decisions,
                        "histories": [],
                        "fence_acquired": False,
                        "runtime_mutated": False,
                        "journal_mutated": False,
                    }
                fence = self._acquire(observation)
                refreshed = self._observe(
                    plan,
                    reconciliation_id=observation["reconciliation_id"],
                    observed_at_utc=observation["observed_at_utc"],
                )
                if canonical_bytes(refreshed) != canonical_bytes(observation):
                    _reject("IS_RECOVERY_DRIFT", "recovery observation changed before execution")
                pending = build_pending(observation, decision, self.holder_id, fence["recovery_fence_token"])
                self.store.save(pending)

            for _ in range(2):
                assert pending is not None
                if not decisions:
                    decisions.append(pending["decision"])
                pending, reobserve = self._execute_pending(
                    plan, pending, interrupt_after_evidence=interrupt_after_evidence
                )
                interrupt_after_evidence = False
                histories.append(str(self.store.archive(pending)))
                if not reobserve:
                    self.backend.release_recovery_fence(
                        plan["run_id"], self.holder_id, pending["recovery_fence_token"]
                    )
                    fence = None
                    return {
                        "schema_version": "incidentseal-recovery-execution/v1",
                        "run_id": plan["run_id"],
                        "verification_verdict": pending["decision"]["verification_verdict"],
                        "decisions": decisions,
                        "histories": histories,
                        "fence_acquired": True,
                        "runtime_mutated": any(item["process_action"] != "none" for item in decisions),
                        "journal_mutated": any(item["append"]["evidence_event_type"] is not None for item in decisions),
                    }
                observation = self._observe(plan)
                decision = decide_recovery(observation)
                decisions.append(decision)
                if decision["process_action"] != "none":
                    _reject("IS_RECOVERY_REOBSERVE", "reobserved recovery still requests a process stop")
                pending = build_pending(observation, decision, self.holder_id, fence["recovery_fence_token"])
                self.store.save(pending)
            _reject("IS_RECOVERY_REOBSERVE", "recovery exceeded one required reobservation")
        except RecoveryInterrupted:
            raise
        except (RecoveryError, JournalError, TopologyError):
            raise
        except Exception as error:
            raise RecoveryExecutionError("IS_RECOVERY_INTERNAL", "unexpected recovery executor failure") from error
        finally:
            # A deliberate interruption retains its active database fence until expiry.
            pass
