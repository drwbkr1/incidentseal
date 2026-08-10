from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.journal import validate_record  # noqa: E402
from incidentseal.recovery_surface import (  # noqa: E402
    PendingStore,
    RecoveryExecutionError,
    RecoveryExecutor,
    RecoveryInterrupted,
    _deterministic_uuid,
    build_pending,
)


MANIFEST = "sha256:" + "4" * 64
ROOT_DIGEST = "sha256:" + "5" * 64


class FakeBackend:
    def __init__(self, *, lease_status: str = "expired", runtime_ownership: str = "exact", runtime_state: str = "absent") -> None:
        self.trace: list[str] = []
        self.journal = {
            "event_count": 2,
            "last_sequence": 1,
            "root_digest": ROOT_DIGEST,
            "lifecycle": "running",
            "verdict": None,
            "terminal": False,
            "manifest_digest": MANIFEST,
            "approval_digest": MANIFEST,
        }
        self.lease_status = lease_status
        self.runtime_ownership = runtime_ownership
        self.runtime_state = runtime_state
        self.runtime_exit = 42 if runtime_state == "exited_nonzero" else (0 if runtime_state == "exited_zero" else None)
        self.active_holder: str | None = None
        self.recovery_token = 0
        self.records: dict[str, dict] = {}

    def query_journal(self, run_id: str) -> dict:
        self.trace.append("query-journal")
        return deepcopy(self.journal)

    def query_workflow_lease(self, run_id: str, observed_at_utc: str) -> dict:
        self.trace.append("query-lease")
        return {
            "status": self.lease_status,
            "holder_id": _deterministic_uuid("workflow-holder"),
            "fence_token": 7,
            "expires_at_utc": "2026-08-10T01:00:00Z" if self.lease_status == "expired" else "2099-08-10T01:00:00Z",
        }

    def inspect_runtime(self, runtime_spec: dict) -> dict:
        self.trace.append("inspect-runtime")
        state = self.runtime_state
        return {
            "ownership": self.runtime_ownership,
            "process_state": state,
            "container_state": state,
            "process_exit_code": self.runtime_exit,
            "container_exit_code": self.runtime_exit,
        }

    def acquire_recovery_fence(self, run_id: str, workflow_fence_token: int, recovery_holder_id: str, expires_at_utc: str) -> dict:
        self.trace.append("acquire-fence")
        if self.active_holder is not None and self.active_holder != recovery_holder_id:
            raise RecoveryExecutionError("IS_RECOVERY_ACTIVE_OWNER", "another holder is active")
        if self.active_holder is None:
            self.recovery_token += 1
            self.active_holder = recovery_holder_id
        return {"recovery_holder_id": recovery_holder_id, "recovery_fence_token": self.recovery_token}

    def release_recovery_fence(self, run_id: str, recovery_holder_id: str, recovery_fence_token: int) -> None:
        self.trace.append("release-fence")
        if self.active_holder != recovery_holder_id or self.recovery_token != recovery_fence_token:
            raise RecoveryExecutionError("IS_RECOVERY_FENCE", "release differs")
        self.active_holder = None

    def append_record(self, record: dict) -> dict:
        self.trace.append("append")
        validate_record(record)
        identity = record["idempotency_key"]
        if identity in self.records:
            if self.records[identity] != record:
                raise RecoveryExecutionError("IS_RECOVERY_APPEND", "replay bytes differ")
            disposition = "replayed"
        else:
            if record["event"]["sequence"] != self.journal["event_count"] or record["previous_link_digest"] != self.journal["root_digest"]:
                raise RecoveryExecutionError("IS_RECOVERY_APPEND", "journal predecessor differs")
            self.records[identity] = deepcopy(record)
            event = record["event"]
            self.journal.update({
                "event_count": self.journal["event_count"] + 1,
                "last_sequence": event["sequence"],
                "root_digest": record["link_digest"],
                "lifecycle": event["lifecycle"],
                "verdict": event["verdict"],
                "terminal": event["terminal"],
            })
            disposition = "inserted"
        event = record["event"]
        return {
            "disposition": disposition,
            "run_id": event["run_id"],
            "sequence": event["sequence"],
            "idempotency_key": identity,
            "event_digest": record["event_digest"],
            "link_digest": record["link_digest"],
            "event_count": self.journal["event_count"],
            "root_digest": self.journal["root_digest"],
            "lifecycle": event["lifecycle"],
            "verdict": event["verdict"],
            "terminal": event["terminal"],
        }

    def stop_runtime(self, runtime_spec: dict, recovery_holder_id: str, recovery_fence_token: int) -> dict:
        self.trace.append("stop-runtime")
        if self.active_holder != recovery_holder_id or self.runtime_ownership != "exact" or self.runtime_state != "running":
            raise RecoveryExecutionError("IS_RECOVERY_RUNTIME", "stop lacks authority")
        self.runtime_state = "absent"
        self.runtime_exit = None
        return {"container_id": runtime_spec["container_id"], "exit_code": 137, "removed": True}

    def replay_step(self, plan: dict, decision: dict) -> dict:
        self.trace.append("replay-step")
        plan["boundary"]["phase"] = "result_committed"
        plan["effects"].update({"artifact": "matching", "database": "matching", "receipt": "absent"})
        return {"decision_digest": decision["decision_digest"], "artifact_digest": "sha256:" + "6" * 64}


def plan(*, request: str = "reconcile", authority_status: str = "MATCH", effects: dict | None = None) -> dict:
    observed = MANIFEST if authority_status == "MATCH" else ("sha256:" + "7" * 64 if authority_status == "MISMATCH" else None)
    return {
        "schema_version": "incidentseal-recovery-plan/v1",
        "run_id": _deterministic_uuid("run"),
        "request": request,
        "interruption": "operator_cancel" if request == "cancel" else "host_crash",
        "authority": {
            "expected_manifest_digest": MANIFEST,
            "approval_status": authority_status,
            "observed_approval_digest": observed,
        },
        "boundary": {"step_id": "recovery.test", "attempt": 1, "phase": "dispatched", "replay_policy": "idempotent"},
        "effects": effects or {"artifact": "absent", "database": "absent", "receipt": "absent"},
        "runtime": {
            "container_id": "sha256:" + "8" * 64,
            "container_name": "incidentseal-test-run-" + _deterministic_uuid("run"),
            "image_id": "sha256:" + "9" * 64,
            "contract_digest": "sha256:" + "a" * 64,
            "workflow_holder_id": _deterministic_uuid("workflow-holder"),
            "workflow_fence_token": 7,
        },
    }


class RecoverySurfaceTests(unittest.TestCase):
    def test_repository_custody_is_rejected_before_creation(self) -> None:
        with self.assertRaises(RecoveryExecutionError) as raised:
            PendingStore(ROOT / ".incidentseal-recovery-forbidden")
        self.assertEqual(raised.exception.code, "IS_RECOVERY_CUSTODY")
        self.assertFalse((ROOT / ".incidentseal-recovery-forbidden").exists())

    def test_active_and_unowned_runtime_defer_without_fence_or_append(self) -> None:
        for backend in (
            FakeBackend(lease_status="active", runtime_state="running"),
            FakeBackend(runtime_ownership="unowned", runtime_state="running"),
        ):
            with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-test-") as temporary:
                result = RecoveryExecutor(
                    backend, Path(temporary) / "state", _deterministic_uuid("recovery-holder")
                ).reconcile(plan(effects={"artifact": "unknown", "database": "unknown", "receipt": "unknown"}))
            self.assertEqual(result["verification_verdict"], "INCONCLUSIVE")
            self.assertNotIn("acquire-fence", backend.trace)
            self.assertNotIn("append", backend.trace)
            self.assertNotIn("stop-runtime", backend.trace)

    def test_fenced_stop_reobserves_before_cancellation_terminal(self) -> None:
        backend = FakeBackend(runtime_state="running")
        with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-test-") as temporary:
            result = RecoveryExecutor(
                backend, Path(temporary) / "state", _deterministic_uuid("recovery-holder")
            ).reconcile(plan(request="cancel"))
        self.assertEqual([item["disposition"] for item in result["decisions"]], ["stop_then_reconcile", "cancel"])
        self.assertEqual(backend.journal["lifecycle"], "cancelled")
        self.assertIsNone(backend.journal["verdict"])
        self.assertLess(backend.trace.index("acquire-fence"), backend.trace.index("stop-runtime"))
        stop_index = backend.trace.index("stop-runtime")
        self.assertIn("inspect-runtime", backend.trace[stop_index + 1 :])

    def test_interrupted_terminal_append_resumes_exact_evidence(self) -> None:
        backend = FakeBackend(runtime_state="exited_nonzero")
        holder = _deterministic_uuid("recovery-holder")
        with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-test-") as temporary:
            root = Path(temporary) / "state"
            executor = RecoveryExecutor(backend, root, holder)
            with self.assertRaises(RecoveryInterrupted):
                executor.reconcile(plan(), interrupt_after_evidence=True)
            self.assertEqual(backend.journal["event_count"], 3)
            result = RecoveryExecutor(backend, root, holder).reconcile(plan())
            self.assertFalse((root / f"{plan()['run_id']}.pending.json").exists())
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertEqual(backend.journal["event_count"], 4)
        self.assertEqual(backend.journal["lifecycle"], "failed")
        self.assertIsNone(backend.journal["verdict"])
        self.assertGreaterEqual(backend.trace.count("append"), 3)

    def test_safe_replay_is_fenced_and_records_null_verdict_evidence(self) -> None:
        backend = FakeBackend(runtime_state="absent")
        value = plan()
        value["boundary"]["phase"] = "before_dispatch"
        with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-test-") as temporary:
            result = RecoveryExecutor(
                backend, Path(temporary) / "state", _deterministic_uuid("recovery-holder")
            ).reconcile(value)
        self.assertEqual(result["decisions"][0]["disposition"], "resume")
        self.assertIn("replay-step", backend.trace)
        self.assertLess(backend.trace.index("acquire-fence"), backend.trace.index("replay-step"))
        self.assertIsNone(backend.journal["verdict"])

    def test_pending_records_are_closed_and_terminal_verdict_remains_null(self) -> None:
        backend = FakeBackend(runtime_state="exited_nonzero")
        value = plan()
        with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-test-") as temporary:
            executor = RecoveryExecutor(backend, Path(temporary) / "state", _deterministic_uuid("recovery-holder"))
            observation = executor._observe(value)
            decision = __import__("incidentseal.recovery", fromlist=["decide_recovery"]).decide_recovery(observation)
            pending = build_pending(observation, decision, executor.holder_id, 1)
        self.assertEqual(set(pending), {
            "schema_version", "run_id", "recovery_holder_id", "recovery_fence_token", "observation", "decision",
            "evidence_record", "terminal_record", "evidence_appended", "terminal_appended", "replay_completed",
            "process_stopped", "append_results", "replay_receipt", "process_receipt", "status",
        })
        self.assertIsNone(pending["evidence_record"]["event"]["verdict"])
        self.assertIsNone(pending["terminal_record"]["event"]["verdict"])


if __name__ == "__main__":
    unittest.main()
