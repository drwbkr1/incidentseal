"""Dependency-free interruption-recovery contract and deterministic classifier."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .manifest import canonical_bytes


SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TIME_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
STEP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

OBSERVATION_FIELDS = {
    "schema_version",
    "reconciliation_id",
    "run_id",
    "observed_at_utc",
    "request",
    "interruption",
    "authority",
    "journal",
    "boundary",
    "lease",
    "runtime",
    "effects",
}
AUTHORITY_FIELDS = {"expected_manifest_digest", "approval_status", "observed_approval_digest"}
JOURNAL_FIELDS = {
    "event_count",
    "last_sequence",
    "root_digest",
    "lifecycle",
    "verdict",
    "terminal",
    "manifest_digest",
    "approval_digest",
}
BOUNDARY_FIELDS = {"step_id", "attempt", "phase", "replay_policy"}
LEASE_FIELDS = {"status", "holder_id", "fence_token", "expires_at_utc"}
RUNTIME_FIELDS = {
    "ownership",
    "process_state",
    "container_state",
    "process_exit_code",
    "container_exit_code",
}
EFFECT_FIELDS = {"artifact", "database", "receipt"}
DECISION_FIELDS = {
    "schema_version",
    "reconciliation_id",
    "run_id",
    "observation_digest",
    "verification_verdict",
    "disposition",
    "reason_code",
    "process_action",
    "replay_step",
    "next_phase",
    "append",
    "decision_digest",
}
APPEND_FIELDS = {"evidence_event_type", "terminal_event_type", "terminal_lifecycle", "run_verdict"}

APPROVAL_STATUSES = {"MATCH", "MISMATCH", "MISSING", "EXPIRED", "INVALID"}
INTERRUPTIONS = {"host_crash", "operator_cancel", "process_exit", "orphan_detected"}
PHASES = {"before_dispatch", "dispatched", "result_committed", "evidence_committed"}
LEASE_STATUSES = {"active", "expired", "missing", "invalid"}
RUNTIME_STATES = {"absent", "running", "exited_zero", "exited_nonzero", "unknown"}
EFFECT_STATES = {"absent", "matching", "conflicting", "unknown"}
VERDICTS = {"PASS", "FAIL", "INCONCLUSIVE", "INVALID"}
DISPOSITIONS = {"resume", "continue", "stop_then_reconcile", "cancel", "fail", "stale", "defer"}
REASON_CODES = {
    "IS_RECOVERY_ACTIVE_OWNER",
    "IS_RECOVERY_LEASE_UNAVAILABLE",
    "IS_RECOVERY_UNOWNED_RUNTIME",
    "IS_RECOVERY_AUTHORITY_STALE",
    "IS_RECOVERY_AUTHORITY_UNAVAILABLE",
    "IS_RECOVERY_CANCEL_PENDING",
    "IS_RECOVERY_CANCEL_CONFIRMED",
    "IS_RECOVERY_PROCESS_FAILED",
    "IS_RECOVERY_ORPHAN_RUNNING",
    "IS_RECOVERY_RUNTIME_AMBIGUOUS",
    "IS_RECOVERY_EFFECTS_AMBIGUOUS",
    "IS_RECOVERY_REPLAY_UNSAFE",
    "IS_RECOVERY_SAFE_REPLAY",
    "IS_RECOVERY_EFFECTS_COMMITTED",
    "IS_RECOVERY_EFFECTS_CONFLICT",
}
NEXT_PHASES = {"dispatch", "record_evidence", "continue_run", "reobserve", "none"}


class RecoveryError(ValueError):
    """A stable fail-closed recovery-contract rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise RecoveryError(code, message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_RECOVERY_SCHEMA", f"{label} fields differ")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        _reject("IS_RECOVERY_SCHEMA", f"{label} is not a lowercase SHA-256 digest")
    return value


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        _reject("IS_RECOVERY_SCHEMA", f"{label} is not a lowercase UUIDv4")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIME_RE.fullmatch(value) is None:
        _reject("IS_RECOVERY_SCHEMA", f"{label} is not a UTC timestamp")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > 9007199254740991:
        _reject("IS_RECOVERY_SCHEMA", f"{label} is not a bounded integer")
    return value


def _exit_code(value: Any, state: str, label: str) -> None:
    if state in {"absent", "running", "unknown"}:
        if value is not None:
            _reject("IS_RECOVERY_RUNTIME", f"{label} exit code exists without an exited runtime")
        return
    if not isinstance(value, int) or isinstance(value, bool) or not -2147483648 <= value <= 4294967295:
        _reject("IS_RECOVERY_RUNTIME", f"{label} exit code is invalid")
    if state == "exited_zero" and value != 0:
        _reject("IS_RECOVERY_RUNTIME", f"{label} zero exit state differs")
    if state == "exited_nonzero" and value == 0:
        _reject("IS_RECOVERY_RUNTIME", f"{label} nonzero exit state differs")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_observation(value: Any) -> dict[str, Any]:
    """Validate one closed recovery observation and its cross-field invariants."""

    observation = _exact(value, OBSERVATION_FIELDS, "observation")
    if observation["schema_version"] != "incidentseal-recovery-observation/v1":
        _reject("IS_RECOVERY_SCHEMA", "observation schema version differs")
    _uuid(observation["reconciliation_id"], "reconciliation_id")
    _uuid(observation["run_id"], "run_id")
    _time(observation["observed_at_utc"], "observed_at_utc")
    if observation["request"] not in {"reconcile", "cancel"}:
        _reject("IS_RECOVERY_SCHEMA", "recovery request differs")
    if observation["interruption"] not in INTERRUPTIONS:
        _reject("IS_RECOVERY_SCHEMA", "interruption kind differs")
    if observation["request"] == "cancel" and observation["interruption"] != "operator_cancel":
        _reject("IS_RECOVERY_STATE", "cancel request does not name operator cancellation")

    authority = _exact(observation["authority"], AUTHORITY_FIELDS, "authority")
    expected = _sha(authority["expected_manifest_digest"], "expected manifest digest")
    status = authority["approval_status"]
    if status not in APPROVAL_STATUSES:
        _reject("IS_RECOVERY_AUTHORITY", "approval status differs")
    observed = authority["observed_approval_digest"]
    if status == "MATCH":
        if _sha(observed, "observed approval digest") != expected:
            _reject("IS_RECOVERY_AUTHORITY", "MATCH approval digest differs")
    elif status == "MISMATCH":
        if _sha(observed, "observed approval digest") == expected:
            _reject("IS_RECOVERY_AUTHORITY", "MISMATCH approval digest equals expected authority")
    elif status == "EXPIRED":
        _sha(observed, "expired approval digest")
    elif observed is not None:
        _reject("IS_RECOVERY_AUTHORITY", "missing or invalid approval has a digest")

    journal = _exact(observation["journal"], JOURNAL_FIELDS, "journal")
    event_count = _integer(journal["event_count"], "journal event_count", 1)
    last_sequence = _integer(journal["last_sequence"], "journal last_sequence")
    if event_count != last_sequence + 1:
        _reject("IS_RECOVERY_JOURNAL", "journal count and last sequence differ")
    _sha(journal["root_digest"], "journal root digest")
    if journal["lifecycle"] not in {"queued", "running"} or journal["verdict"] is not None or journal["terminal"] is not False:
        _reject("IS_RECOVERY_JOURNAL", "recovery requires one nonterminal null-verdict run")
    manifest = _sha(journal["manifest_digest"], "journal manifest digest")
    approval = _sha(journal["approval_digest"], "journal approval digest")
    if manifest != approval or manifest != expected:
        _reject("IS_RECOVERY_AUTHORITY", "journal authority differs from the expected manifest")

    boundary = _exact(observation["boundary"], BOUNDARY_FIELDS, "boundary")
    if not isinstance(boundary["step_id"], str) or STEP_RE.fullmatch(boundary["step_id"]) is None:
        _reject("IS_RECOVERY_SCHEMA", "step_id is invalid")
    _integer(boundary["attempt"], "boundary attempt", 1)
    if boundary["phase"] not in PHASES or boundary["replay_policy"] not in {"idempotent", "never"}:
        _reject("IS_RECOVERY_BOUNDARY", "boundary phase or replay policy differs")

    lease = _exact(observation["lease"], LEASE_FIELDS, "lease")
    if lease["status"] not in LEASE_STATUSES:
        _reject("IS_RECOVERY_LEASE", "lease status differs")
    if lease["status"] in {"active", "expired"}:
        _uuid(lease["holder_id"], "lease holder_id")
        _integer(lease["fence_token"], "lease fence_token", 1)
        _time(lease["expires_at_utc"], "lease expires_at_utc")
    elif lease["status"] == "missing":
        if any(lease[name] is not None for name in ("holder_id", "fence_token", "expires_at_utc")):
            _reject("IS_RECOVERY_LEASE", "missing lease retains identity fields")

    runtime = _exact(observation["runtime"], RUNTIME_FIELDS, "runtime")
    if runtime["ownership"] not in {"exact", "unowned", "ambiguous"}:
        _reject("IS_RECOVERY_RUNTIME", "runtime ownership differs")
    for state_name, code_name, label in (
        ("process_state", "process_exit_code", "process"),
        ("container_state", "container_exit_code", "container"),
    ):
        state = runtime[state_name]
        if state not in RUNTIME_STATES:
            _reject("IS_RECOVERY_RUNTIME", f"{label} state differs")
        _exit_code(runtime[code_name], state, label)
    if runtime["process_state"] == "absent" and runtime["container_state"] == "absent" and runtime["ownership"] != "exact":
        _reject("IS_RECOVERY_RUNTIME", "absent runtime must retain exact expected ownership binding")

    effects = _exact(observation["effects"], EFFECT_FIELDS, "effects")
    if any(effects[name] not in EFFECT_STATES for name in EFFECT_FIELDS):
        _reject("IS_RECOVERY_EFFECTS", "effect state differs")
    if boundary["phase"] == "before_dispatch" and any(effects[name] != "absent" for name in EFFECT_FIELDS):
        _reject("IS_RECOVERY_BOUNDARY", "before-dispatch boundary contains effects")
    return observation


def observation_digest(value: Any) -> str:
    observation = validate_observation(value)
    return _digest(
        {
            "schema_version": "incidentseal-recovery-observation-identity/v1",
            "observation": observation,
        }
    )


def _make_decision(
    observation: dict[str, Any],
    *,
    verification_verdict: str,
    disposition: str,
    reason_code: str,
    process_action: str = "none",
    replay_step: bool = False,
    next_phase: str = "none",
    evidence_event: bool = True,
    terminal_event_type: str | None = None,
    terminal_lifecycle: str | None = None,
) -> dict[str, Any]:
    core = {
        "schema_version": "incidentseal-recovery-decision/v1",
        "reconciliation_id": observation["reconciliation_id"],
        "run_id": observation["run_id"],
        "observation_digest": observation_digest(observation),
        "verification_verdict": verification_verdict,
        "disposition": disposition,
        "reason_code": reason_code,
        "process_action": process_action,
        "replay_step": replay_step,
        "next_phase": next_phase,
        "append": {
            "evidence_event_type": "evidence.recorded" if evidence_event else None,
            "terminal_event_type": terminal_event_type,
            "terminal_lifecycle": terminal_lifecycle,
            "run_verdict": None,
        },
    }
    decision = dict(core)
    decision["decision_digest"] = _digest(
        {
            "schema_version": "incidentseal-recovery-decision-identity/v1",
            "decision": core,
        }
    )
    return decision


def decide_recovery(value: Any) -> dict[str, Any]:
    """Return the one deterministic action allowed by the frozen observation."""

    observation = validate_observation(value)
    lease = observation["lease"]
    runtime = observation["runtime"]
    authority = observation["authority"]
    effects = observation["effects"]
    boundary = observation["boundary"]
    states = (runtime["process_state"], runtime["container_state"])
    active_runtime = "running" in states
    unknown_runtime = "unknown" in states
    nonzero_runtime = "exited_nonzero" in states
    runtime_observed = any(state != "absent" for state in states)

    if lease["status"] == "active":
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_ACTIVE_OWNER",
            evidence_event=False,
        )
    if lease["status"] in {"missing", "invalid"}:
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_LEASE_UNAVAILABLE",
            evidence_event=False,
        )
    if runtime_observed and runtime["ownership"] != "exact":
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_UNOWNED_RUNTIME",
            evidence_event=False,
        )
    if authority["approval_status"] == "MISMATCH":
        if active_runtime:
            return _make_decision(
                observation,
                verification_verdict="PASS",
                disposition="stop_then_reconcile",
                reason_code="IS_RECOVERY_AUTHORITY_STALE",
                process_action="stop_owned_and_wait",
                next_phase="reobserve",
            )
        return _make_decision(
            observation,
            verification_verdict="PASS",
            disposition="stale",
            reason_code="IS_RECOVERY_AUTHORITY_STALE",
            terminal_event_type="run.stale",
            terminal_lifecycle="stale",
        )
    if authority["approval_status"] != "MATCH":
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_AUTHORITY_UNAVAILABLE",
            evidence_event=False,
        )
    if observation["request"] == "cancel":
        if active_runtime:
            return _make_decision(
                observation,
                verification_verdict="PASS",
                disposition="stop_then_reconcile",
                reason_code="IS_RECOVERY_CANCEL_PENDING",
                process_action="stop_owned_and_wait",
                next_phase="reobserve",
            )
        if unknown_runtime:
            return _make_decision(
                observation,
                verification_verdict="INCONCLUSIVE",
                disposition="defer",
                reason_code="IS_RECOVERY_RUNTIME_AMBIGUOUS",
            )
        return _make_decision(
            observation,
            verification_verdict="PASS",
            disposition="cancel",
            reason_code="IS_RECOVERY_CANCEL_CONFIRMED",
            terminal_event_type="run.cancelled",
            terminal_lifecycle="cancelled",
        )
    if nonzero_runtime:
        return _make_decision(
            observation,
            verification_verdict="PASS",
            disposition="fail",
            reason_code="IS_RECOVERY_PROCESS_FAILED",
            terminal_event_type="run.failed",
            terminal_lifecycle="failed",
        )
    if active_runtime:
        return _make_decision(
            observation,
            verification_verdict="PASS",
            disposition="stop_then_reconcile",
            reason_code="IS_RECOVERY_ORPHAN_RUNNING",
            process_action="stop_owned_and_wait",
            next_phase="reobserve",
        )
    if unknown_runtime:
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_RUNTIME_AMBIGUOUS",
        )

    effect_values = tuple(effects[name] for name in ("artifact", "database", "receipt"))
    if "conflicting" in effect_values:
        return _make_decision(
            observation,
            verification_verdict="FAIL",
            disposition="fail",
            reason_code="IS_RECOVERY_EFFECTS_CONFLICT",
            terminal_event_type="run.failed",
            terminal_lifecycle="failed",
        )
    if "unknown" in effect_values:
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_EFFECTS_AMBIGUOUS",
        )

    if boundary["phase"] in {"before_dispatch", "dispatched"} and all(value == "absent" for value in effect_values):
        if boundary["replay_policy"] == "idempotent":
            return _make_decision(
                observation,
                verification_verdict="PASS",
                disposition="resume",
                reason_code="IS_RECOVERY_SAFE_REPLAY",
                replay_step=True,
                next_phase="dispatch",
            )
        return _make_decision(
            observation,
            verification_verdict="INCONCLUSIVE",
            disposition="defer",
            reason_code="IS_RECOVERY_REPLAY_UNSAFE",
        )

    committed = effects["artifact"] == "matching" and effects["database"] == "matching"
    if committed and effects["receipt"] in {"absent", "matching"}:
        return _make_decision(
            observation,
            verification_verdict="PASS",
            disposition="continue",
            reason_code="IS_RECOVERY_EFFECTS_COMMITTED",
            next_phase="record_evidence" if effects["receipt"] == "absent" else "continue_run",
        )
    return _make_decision(
        observation,
        verification_verdict="FAIL",
        disposition="fail",
        reason_code="IS_RECOVERY_EFFECTS_CONFLICT",
        terminal_event_type="run.failed",
        terminal_lifecycle="failed",
    )


def validate_decision(value: Any, observation_value: Any) -> dict[str, Any]:
    """Validate a closed decision and require exact classifier equivalence."""

    decision = _exact(value, DECISION_FIELDS, "decision")
    if decision["schema_version"] != "incidentseal-recovery-decision/v1":
        _reject("IS_RECOVERY_SCHEMA", "decision schema version differs")
    _uuid(decision["reconciliation_id"], "decision reconciliation_id")
    _uuid(decision["run_id"], "decision run_id")
    _sha(decision["observation_digest"], "decision observation_digest")
    _sha(decision["decision_digest"], "decision digest")
    if decision["verification_verdict"] not in VERDICTS:
        _reject("IS_RECOVERY_SCHEMA", "decision verification verdict differs")
    if decision["disposition"] not in DISPOSITIONS or decision["reason_code"] not in REASON_CODES:
        _reject("IS_RECOVERY_SCHEMA", "decision disposition or reason differs")
    if decision["process_action"] not in {"none", "stop_owned_and_wait"}:
        _reject("IS_RECOVERY_SCHEMA", "decision process action differs")
    if not isinstance(decision["replay_step"], bool) or decision["next_phase"] not in NEXT_PHASES:
        _reject("IS_RECOVERY_SCHEMA", "decision replay or next phase differs")
    append = _exact(decision["append"], APPEND_FIELDS, "decision append plan")
    if append["evidence_event_type"] not in {None, "evidence.recorded"}:
        _reject("IS_RECOVERY_SCHEMA", "evidence event plan differs")
    terminal_pairs = {
        (None, None),
        ("run.cancelled", "cancelled"),
        ("run.failed", "failed"),
        ("run.stale", "stale"),
    }
    if (append["terminal_event_type"], append["terminal_lifecycle"]) not in terminal_pairs:
        _reject("IS_RECOVERY_STATE", "terminal event plan differs")
    if append["run_verdict"] is not None:
        _reject("IS_RECOVERY_VERDICT", "recovery action fabricated a run verdict")
    expected = decide_recovery(observation_value)
    if canonical_bytes(decision) != canonical_bytes(expected):
        _reject("IS_RECOVERY_DECISION", "decision differs from the deterministic classifier")
    return decision
