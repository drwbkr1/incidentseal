#!/usr/bin/env python3
"""Validate the frozen append-only event journal contract without dependencies or runtime."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import ManifestError, canonical_bytes, strict_load_bytes  # noqa: E402


LOCK = ROOT / "requirements" / "event-journal-contract.lock.json"
VECTORS = ROOT / "fixtures" / "journal" / "vectors.json"
GENESIS = "sha256:" + "0" * 64
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TIME_RE = re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
RECORD_FIELDS = {"schema_version", "idempotency_key", "event_digest", "previous_link_digest", "link_digest", "event"}
EVENT_FIELDS = {"schema_version", "event_id", "run_id", "sequence", "occurred_at_utc", "event_type", "lifecycle", "verdict", "terminal", "manifest_digest", "approval_digest", "payload", "error"}
RESULT_FIELDS = {"schema_version", "disposition", "run_id", "sequence", "idempotency_key", "event_digest", "link_digest", "event_count", "root_digest", "lifecycle", "verdict", "terminal"}
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
TRANSITIONS = {
    "queued": {"running", "cancelled", "failed", "stale", "superseded"},
    "running": {"running", "completed", "cancelled", "failed", "stale", "superseded"},
}
EXPECTED_PATHS = (
    "docs/decisions/ADR-0006-append-only-event-idempotency.md",
    "docs/event-journal-contract.md",
    "docs/event-journal-mutation-plan.md",
    "fixtures/journal/mutations.json",
    "fixtures/journal/record.invalid.minimal.json",
    "fixtures/journal/record.valid.json",
    "fixtures/journal/result.valid.json",
    "fixtures/journal/vectors.json",
    "requirements/meta-validation.lock",
    "schemas/event-journal-record-v1.schema.json",
    "schemas/event-journal-result-v1.schema.json",
    "schemas/run-event-v1.schema.json",
    "scripts/run_event_journal_meta_validation.py",
    "scripts/test_event_journal_contract_mutations.py",
    "scripts/validate_event_journal_contract.py",
    "scripts/validate_event_journal_schema_meta.py",
    "src/incidentseal/manifest.py",
)


class JournalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise JournalError(code, message)


def load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except (OSError, ManifestError) as error:
        raise JournalError("IS_JOURNAL_JSON", f"could not strictly load {path.name}") from error


def digest_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        reject("IS_JOURNAL_SCHEMA", f"{label} fields differ")
    return value


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        reject("IS_JOURNAL_SCHEMA", f"{label} is not a lowercase SHA-256 digest")
    return value


def require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        reject("IS_JOURNAL_SCHEMA", f"{label} is not a lowercase UUIDv4")
    return value


def validate_lock() -> str:
    value = load(LOCK)
    if not isinstance(value, dict) or value.get("schema_version") != "incidentseal-event-journal-contract-lock/v1":
        reject("IS_JOURNAL_LOCK", "event journal contract lock version differs")
    entries = value.get("files")
    if not isinstance(entries, list):
        reject("IS_JOURNAL_LOCK", "event journal lock files are absent")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if tuple(paths) != EXPECTED_PATHS or len(paths) != len(set(paths)):
        reject("IS_JOURNAL_LOCK", "event journal lock path set differs")
    for entry in entries:
        if digest_file(ROOT / entry["path"]) != entry.get("sha256"):
            reject("IS_JOURNAL_LOCK", f"event journal lock drift: {entry['path']}")
    return digest_file(LOCK)


def validate_event(event_value: Any) -> dict[str, Any]:
    event = exact(event_value, EVENT_FIELDS, "event")
    if event["schema_version"] != "incidentseal-run-event/v1":
        reject("IS_JOURNAL_SCHEMA", "event schema version differs")
    require_uuid(event["event_id"], "event_id")
    require_uuid(event["run_id"], "run_id")
    sequence = event["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= 9007199254740991:
        reject("IS_JOURNAL_SEQUENCE", "event sequence is invalid")
    if not isinstance(event["occurred_at_utc"], str) or TIME_RE.fullmatch(event["occurred_at_utc"]) is None:
        reject("IS_JOURNAL_SCHEMA", "event timestamp is invalid")
    lifecycle = event["lifecycle"]
    if lifecycle not in LIFECYCLES or event["event_type"] not in EVENT_TYPES[lifecycle]:
        reject("IS_JOURNAL_STATE", "event type and lifecycle differ")
    if not isinstance(event["terminal"], bool) or event["terminal"] != (lifecycle in TERMINAL):
        reject("IS_JOURNAL_STATE", "event terminal state differs")
    if lifecycle == "completed":
        if event["verdict"] not in VERDICTS:
            reject("IS_JOURNAL_STATE", "completed event requires a verdict")
    elif event["verdict"] is not None:
        reject("IS_JOURNAL_STATE", "non-completed event cannot carry a verdict")
    manifest = require_sha(event["manifest_digest"], "manifest_digest")
    approval = require_sha(event["approval_digest"], "approval_digest")
    if manifest != approval:
        reject("IS_JOURNAL_AUTHORITY", "event manifest and approval digests differ")
    if not isinstance(event["payload"], dict):
        reject("IS_JOURNAL_SCHEMA", "event payload is not an object")
    if event["error"] is not None:
        error = exact(event["error"], {"code", "message", "retriable"}, "event error")
        if not isinstance(error["code"], str) or not error["code"].startswith("IS_") or not isinstance(error["message"], str) or not error["message"] or not isinstance(error["retriable"], bool):
            reject("IS_JOURNAL_SCHEMA", "event error is invalid")
    if lifecycle == "stale":
        payload = exact(event["payload"], {"expected_authority_digest", "observed_authority_digest", "reason"}, "stale payload")
        expected = require_sha(payload["expected_authority_digest"], "expected stale authority")
        observed = require_sha(payload["observed_authority_digest"], "observed stale authority")
        if expected != manifest or expected == observed or not isinstance(payload["reason"], str) or not payload["reason"]:
            reject("IS_JOURNAL_STATE", "stale authority evidence is invalid")
    if lifecycle == "superseded":
        payload = exact(event["payload"], {"superseded_by_run_id", "reason"}, "superseded payload")
        successor = require_uuid(payload["superseded_by_run_id"], "superseded_by_run_id")
        if successor == event["run_id"] or not isinstance(payload["reason"], str) or not payload["reason"]:
            reject("IS_JOURNAL_STATE", "supersession evidence is invalid")
    return event


def validate_record(record_value: Any) -> dict[str, Any]:
    record = exact(record_value, RECORD_FIELDS, "record")
    if record["schema_version"] != "incidentseal-event-journal-record/v1":
        reject("IS_JOURNAL_SCHEMA", "journal record version differs")
    event = validate_event(record["event"])
    for name in ("idempotency_key", "event_digest", "previous_link_digest", "link_digest"):
        require_sha(record[name], name)
    event_digest = digest_value(event)
    if record["event_digest"] != event_digest:
        reject("IS_JOURNAL_EVENT_DIGEST", "event digest differs")
    idempotency = digest_value(
        {
            "schema_version": "incidentseal-event-idempotency/v1",
            "run_id": event["run_id"],
            "sequence": event["sequence"],
            "event_digest": event_digest,
            "previous_link_digest": record["previous_link_digest"],
        }
    )
    if record["idempotency_key"] != idempotency:
        reject("IS_JOURNAL_IDEMPOTENCY", "idempotency key differs")
    link = digest_value(
        {
            "schema_version": "incidentseal-event-link/v1",
            "sequence": event["sequence"],
            "event_digest": event_digest,
            "previous_link_digest": record["previous_link_digest"],
        }
    )
    if record["link_digest"] != link:
        reject("IS_JOURNAL_LINK", "link digest differs")
    return record


def result_for(record: dict[str, Any], disposition: str, event_count: int) -> dict[str, Any]:
    event = record["event"]
    return {
        "schema_version": "incidentseal-event-journal-result/v1",
        "disposition": disposition,
        "run_id": event["run_id"],
        "sequence": event["sequence"],
        "idempotency_key": record["idempotency_key"],
        "event_digest": record["event_digest"],
        "link_digest": record["link_digest"],
        "event_count": event_count,
        "root_digest": record["link_digest"],
        "lifecycle": event["lifecycle"],
        "verdict": event["verdict"],
        "terminal": event["terminal"],
    }


def validate_result(value: Any) -> dict[str, Any]:
    result = exact(value, RESULT_FIELDS, "journal result")
    if result["schema_version"] != "incidentseal-event-journal-result/v1" or result["disposition"] not in {"inserted", "replayed"}:
        reject("IS_JOURNAL_SCHEMA", "journal result identity differs")
    require_uuid(result["run_id"], "result run_id")
    for name in ("idempotency_key", "event_digest", "link_digest", "root_digest"):
        require_sha(result[name], f"result {name}")
    if not isinstance(result["sequence"], int) or not isinstance(result["event_count"], int) or result["event_count"] != result["sequence"] + 1:
        reject("IS_JOURNAL_SEQUENCE", "journal result count differs")
    if result["lifecycle"] not in LIFECYCLES or not isinstance(result["terminal"], bool):
        reject("IS_JOURNAL_STATE", "journal result state differs")
    return result


class MemoryJournal:
    def __init__(self) -> None:
        self.by_key: dict[str, tuple[bytes, dict[str, Any]]] = {}
        self.event_ids: set[str] = set()
        self.runs: dict[str, list[dict[str, Any]]] = {}

    def append(self, record_value: Any) -> dict[str, Any]:
        if isinstance(record_value, dict) and isinstance(record_value.get("idempotency_key"), str):
            retained = self.by_key.get(record_value["idempotency_key"])
            if retained is not None:
                if retained[0] != canonical_bytes(record_value):
                    reject("IS_JOURNAL_CONFLICT", "idempotency key is retained for different bytes")
                record = retained[1]
                return result_for(record, "replayed", len(self.runs[record["event"]["run_id"]]))
        record = validate_record(record_value)
        event = record["event"]
        run_id = event["run_id"]
        run = self.runs.get(run_id, [])
        if event["event_id"] in self.event_ids:
            reject("IS_JOURNAL_CONFLICT", "event_id is already retained")
        if not run:
            if event["sequence"] != 0 or event["lifecycle"] != "queued" or record["previous_link_digest"] != GENESIS:
                reject("IS_JOURNAL_SEQUENCE", "first event is not queued at genesis sequence zero")
        else:
            prior = run[-1]
            prior_event = prior["event"]
            if prior_event["terminal"]:
                reject("IS_JOURNAL_TERMINAL", "terminal run cannot accept another event")
            if event["sequence"] < len(run):
                reject("IS_JOURNAL_CONFLICT", "run sequence is already retained for different bytes")
            if event["sequence"] != len(run) or record["previous_link_digest"] != prior["link_digest"]:
                reject("IS_JOURNAL_SEQUENCE", "event sequence or predecessor is not contiguous")
            if event["manifest_digest"] != prior_event["manifest_digest"] or event["approval_digest"] != prior_event["approval_digest"]:
                reject("IS_JOURNAL_AUTHORITY", "run authority changed within the journal")
            if event["lifecycle"] not in TRANSITIONS[prior_event["lifecycle"]]:
                reject("IS_JOURNAL_STATE", "lifecycle transition is invalid")
        run.append(deepcopy(record))
        self.runs[run_id] = run
        self.event_ids.add(event["event_id"])
        self.by_key[record["idempotency_key"]] = (canonical_bytes(record), deepcopy(record))
        return result_for(record, "inserted", len(run))

    def events(self, run_id: str) -> list[dict[str, Any]]:
        return deepcopy(self.runs.get(run_id, []))


def validate() -> dict[str, Any]:
    lock_digest = validate_lock()
    vectors = load(VECTORS)
    exact(vectors, {"schema_version", "genesis_digest", "cases"}, "vectors")
    if vectors["schema_version"] != "incidentseal-event-journal-vectors/v1" or vectors["genesis_digest"] != GENESIS:
        reject("IS_JOURNAL_VECTOR", "journal vector identity differs")
    cases = vectors["cases"]
    if not isinstance(cases, list) or [case.get("id") for case in cases if isinstance(case, dict)] != ["completed-pass", "stale-authority", "superseded-attempt"]:
        reject("IS_JOURNAL_VECTOR", "journal vector cases differ")
    record_count = 0
    replay_count = 0
    final_results: dict[str, dict[str, Any]] = {}
    for case in cases:
        exact(case, {"id", "records", "expected"}, "vector case")
        journal = MemoryJournal()
        for record in case["records"]:
            result = journal.append(record)
            if result["disposition"] != "inserted":
                reject("IS_JOURNAL_VECTOR", "new vector record did not insert")
            record_count += 1
        last = case["records"][-1]
        replay = journal.append(deepcopy(last))
        if replay["disposition"] != "replayed" or replay["event_count"] != len(case["records"]):
            reject("IS_JOURNAL_VECTOR", "exact replay changed journal state")
        replay_count += 1
        final = result_for(last, "inserted", len(case["records"]))
        expected = case["expected"]
        for name in ("event_count", "root_digest", "lifecycle", "verdict", "terminal"):
            if final[name] != expected[name]:
                reject("IS_JOURNAL_VECTOR", f"case summary differs: {case['id']} {name}")
        if journal.events(last["event"]["run_id"]) != case["records"]:
            reject("IS_JOURNAL_VECTOR", "ordered read differs from retained records")
        final_results[case["id"]] = final
    if load(ROOT / "fixtures/journal/record.valid.json") != cases[0]["records"][0]:
        reject("IS_JOURNAL_VECTOR", "standalone valid record differs from vector")
    valid_result = validate_result(load(ROOT / "fixtures/journal/result.valid.json"))
    if valid_result != final_results["completed-pass"]:
        reject("IS_JOURNAL_VECTOR", "standalone valid result differs from vector")
    return {
        "schema_version": "incidentseal-event-journal-contract-validation/v1",
        "verdict": "PASS",
        "lock_digest": lock_digest,
        "vector_digest": digest_file(VECTORS),
        "case_count": len(cases),
        "record_count": record_count,
        "exact_replay_count": replay_count,
        "completed_root_digest": final_results["completed-pass"]["root_digest"],
        "stale_root_digest": final_results["stale-authority"]["root_digest"],
        "superseded_root_digest": final_results["superseded-attempt"]["root_digest"],
        "runtime_started": False,
        "third_party_dependencies": 0,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, JournalError) else "IS_JOURNAL_INTERNAL"
        print(json.dumps({"schema_version":"incidentseal-event-journal-contract-validation/v1","verdict":"INVALID","error":{"code":code,"message":str(error)}}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
