"""Dependency-free validation for the locked append-only event journal."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .manifest import ManifestError, canonical_bytes, strict_load_bytes
from .topology import TopologyError


ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATION_LOCK = ROOT / "requirements" / "event-journal-implementation.lock.json"
GENESIS = "sha256:" + "0" * 64
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TIME_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
RECORD_FIELDS = {
    "schema_version", "idempotency_key", "event_digest", "previous_link_digest", "link_digest", "event"
}
EVENT_FIELDS = {
    "schema_version", "event_id", "run_id", "sequence", "occurred_at_utc", "event_type", "lifecycle",
    "verdict", "terminal", "manifest_digest", "approval_digest", "payload", "error"
}
LIFECYCLES = {"queued", "running", "completed", "cancelled", "failed", "stale", "superseded"}
VERDICTS = {"PASS", "FAIL", "INCONCLUSIVE", "INVALID"}
TERMINAL = {"completed", "cancelled", "failed", "stale", "superseded"}
EVENT_TYPES = {
    "queued": {"run.queued"},
    "running": {"run.started", "policy.checked", "step.started", "step.completed", "step.failed", "evidence.recorded"},
    "completed": {"run.completed"},
    "cancelled": {"run.cancelled"},
    "failed": {"run.failed"},
    "stale": {"run.stale"},
    "superseded": {"run.superseded"},
}
EXPECTED_IMPLEMENTATION_PATHS = (
    "containers/migration/001-schema.sql",
    "docs/cli-contract.md",
    "docs/event-journal-implementation.md",
    "requirements/event-journal-contract.lock.json",
    "scripts/test_event_journal_implementation_mutations.py",
    "scripts/validate_event_journal_implementation.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/journal.py",
    "src/incidentseal/journal_surface.py",
    "src/incidentseal/topology.py",
    "tests/test_journal.py",
)


class JournalError(TopologyError):
    """A stable fail-closed journal rejection."""

    def __init__(self, code: str, message: str, *, io_error: bool = False) -> None:
        super().__init__(code, message, io_error=io_error)


def _reject(code: str, message: str, *, io_error: bool = False) -> None:
    raise JournalError(code, message, io_error=io_error)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except OSError as error:
        raise JournalError("IS_JOURNAL_READ", f"required journal file is unavailable: {path.name}", io_error=True) from error
    except ManifestError as error:
        raise JournalError("IS_JOURNAL_JSON", f"journal JSON is invalid: {path.name}") from error


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_JOURNAL_SCHEMA", f"{label} fields differ")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        _reject("IS_JOURNAL_SCHEMA", f"{label} is not a lowercase SHA-256 digest")
    return value


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        _reject("IS_JOURNAL_SCHEMA", f"{label} is not a lowercase UUIDv4")
    return value


def validate_run_id(value: str) -> str:
    """Validate the exact v1 run identifier accepted by the read-only stream."""

    return _uuid(value, "run_id")


def validate_implementation_lock() -> str:
    """Bind the runtime journal surface to its exact reviewed implementation."""

    lock = _load(IMPLEMENTATION_LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-event-journal-implementation-lock/v1":
        _reject("IS_JOURNAL_IMPLEMENTATION", "journal implementation lock version differs")
    entries = lock.get("files")
    if not isinstance(entries, list):
        _reject("IS_JOURNAL_IMPLEMENTATION", "journal implementation lock files are absent")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if tuple(paths) != EXPECTED_IMPLEMENTATION_PATHS or len(paths) != len(set(paths)):
        _reject("IS_JOURNAL_IMPLEMENTATION", "journal implementation lock scope differs")
    for entry in entries:
        path = ROOT / str(entry.get("path", ""))
        expected = entry.get("sha256")
        try:
            observed = _digest(path.read_bytes())
        except OSError as error:
            raise JournalError("IS_JOURNAL_READ", f"locked journal file is unavailable: {path.name}", io_error=True) from error
        if not isinstance(expected, str) or SHA_RE.fullmatch(expected) is None or observed != expected:
            _reject("IS_JOURNAL_IMPLEMENTATION", f"journal implementation drift: {entry.get('path')}")
    return _digest(IMPLEMENTATION_LOCK.read_bytes())


def validate_event(event_value: Any) -> dict[str, Any]:
    """Validate one closed run event independently of its position in a chain."""

    event = _exact(event_value, EVENT_FIELDS, "event")
    if event["schema_version"] != "incidentseal-run-event/v1":
        _reject("IS_JOURNAL_SCHEMA", "event schema version differs")
    _uuid(event["event_id"], "event_id")
    _uuid(event["run_id"], "run_id")
    sequence = event["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= 9007199254740991:
        _reject("IS_JOURNAL_SEQUENCE", "event sequence is invalid")
    if not isinstance(event["occurred_at_utc"], str) or TIME_RE.fullmatch(event["occurred_at_utc"]) is None:
        _reject("IS_JOURNAL_SCHEMA", "event timestamp is invalid")
    lifecycle = event["lifecycle"]
    if lifecycle not in LIFECYCLES or event["event_type"] not in EVENT_TYPES[lifecycle]:
        _reject("IS_JOURNAL_STATE", "event type and lifecycle differ")
    if not isinstance(event["terminal"], bool) or event["terminal"] != (lifecycle in TERMINAL):
        _reject("IS_JOURNAL_STATE", "event terminal state differs")
    if lifecycle == "completed":
        if event["verdict"] not in VERDICTS:
            _reject("IS_JOURNAL_STATE", "completed event requires a verdict")
    elif event["verdict"] is not None:
        _reject("IS_JOURNAL_STATE", "non-completed event cannot carry a verdict")
    manifest = _sha(event["manifest_digest"], "manifest_digest")
    approval = _sha(event["approval_digest"], "approval_digest")
    if manifest != approval:
        _reject("IS_JOURNAL_AUTHORITY", "event manifest and approval digests differ")
    if not isinstance(event["payload"], dict):
        _reject("IS_JOURNAL_SCHEMA", "event payload is not an object")
    if event["error"] is not None:
        error = _exact(event["error"], {"code", "message", "retriable"}, "event error")
        if (
            not isinstance(error["code"], str)
            or re.fullmatch(r"IS_[A-Z0-9_]+", error["code"]) is None
            or not isinstance(error["message"], str)
            or not 1 <= len(error["message"]) <= 1000
            or not isinstance(error["retriable"], bool)
        ):
            _reject("IS_JOURNAL_SCHEMA", "event error is invalid")
    if lifecycle == "stale":
        payload = _exact(event["payload"], {"expected_authority_digest", "observed_authority_digest", "reason"}, "stale payload")
        expected = _sha(payload["expected_authority_digest"], "expected stale authority")
        observed = _sha(payload["observed_authority_digest"], "observed stale authority")
        if expected != manifest or expected == observed or not isinstance(payload["reason"], str) or not payload["reason"]:
            _reject("IS_JOURNAL_STATE", "stale authority evidence is invalid")
    if lifecycle == "superseded":
        payload = _exact(event["payload"], {"superseded_by_run_id", "reason"}, "superseded payload")
        successor = _uuid(payload["superseded_by_run_id"], "superseded_by_run_id")
        if successor == event["run_id"] or not isinstance(payload["reason"], str) or not payload["reason"]:
            _reject("IS_JOURNAL_STATE", "supersession evidence is invalid")
    return event


def validate_record(record_value: Any) -> dict[str, Any]:
    """Validate the closed record and every domain-separated digest."""

    record = _exact(record_value, RECORD_FIELDS, "record")
    if record["schema_version"] != "incidentseal-event-journal-record/v1":
        _reject("IS_JOURNAL_SCHEMA", "journal record version differs")
    event = validate_event(record["event"])
    for name in ("idempotency_key", "event_digest", "previous_link_digest", "link_digest"):
        _sha(record[name], name)
    event_digest = _digest(canonical_bytes(event))
    if record["event_digest"] != event_digest:
        _reject("IS_JOURNAL_EVENT_DIGEST", "event digest differs")
    idempotency = _digest(
        canonical_bytes(
            {
                "schema_version": "incidentseal-event-idempotency/v1",
                "run_id": event["run_id"],
                "sequence": event["sequence"],
                "event_digest": event_digest,
                "previous_link_digest": record["previous_link_digest"],
            }
        )
    )
    if record["idempotency_key"] != idempotency:
        _reject("IS_JOURNAL_IDEMPOTENCY", "idempotency key differs")
    link = _digest(
        canonical_bytes(
            {
                "schema_version": "incidentseal-event-link/v1",
                "sequence": event["sequence"],
                "event_digest": event_digest,
                "previous_link_digest": record["previous_link_digest"],
            }
        )
    )
    if record["link_digest"] != link:
        _reject("IS_JOURNAL_LINK", "link digest differs")
    return record


def canonical_record(record_value: Any) -> tuple[dict[str, Any], bytes]:
    record = validate_record(record_value)
    return record, canonical_bytes(record)


def event_from_canonical_bytes(raw: bytes, *, run_id: str, sequence: int) -> dict[str, Any]:
    """Fail closed if retained bytes are not the exact canonical event requested."""

    try:
        value = strict_load_bytes(raw)
    except ManifestError as error:
        raise JournalError("IS_JOURNAL_DATABASE", "retained event bytes are invalid JSON") from error
    event = validate_event(value)
    if canonical_bytes(event) != raw:
        _reject("IS_JOURNAL_DATABASE", "retained event bytes are not canonical")
    if event["run_id"] != run_id or event["sequence"] != sequence:
        _reject("IS_JOURNAL_DATABASE", "retained event identity or order differs")
    return event


def lifecycle_exit(event: dict[str, Any]) -> int:
    """Map the last retained event to the frozen independent exit semantics."""

    lifecycle = event["lifecycle"]
    if lifecycle in {"queued", "running"}:
        return 11
    if lifecycle == "completed":
        return {"PASS": 0, "FAIL": 10, "INCONCLUSIVE": 11, "INVALID": 12}[event["verdict"]]
    return {"cancelled": 20, "failed": 21, "stale": 22, "superseded": 23}[lifecycle]
