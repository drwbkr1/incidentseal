"""Closed, dependency-free contract for the IncidentSeal evidence dashboard."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .manifest import canonical_bytes


TIME_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH_RE = re.compile(r"^(?:records|requirements|contracts)/[A-Za-z0-9._/-]+$")

SNAPSHOT_FIELDS = {
    "schema_version", "snapshot_id", "generated_at_utc", "source", "authority",
    "trust_boundary", "exits", "states", "source_records", "retained_attempts",
    "non_claims", "verification_verdict", "snapshot_digest",
}
SOURCE_FIELDS = {"repository", "branch", "checkpoint", "tag_object", "peeled_commit", "tree"}
AUTHORITY_FIELDS = {
    "approval_status", "approved_workflow", "workflow_executed", "dashboard_creates_authority",
}
TRUST_FIELDS = {
    "read_only", "bind_host", "allowed_methods", "docker_access", "approval_write_access",
    "repository_write_access", "external_network", "remote_assets", "analytics", "telemetry",
}
EXIT_FIELDS = {"id", "status", "evidence"}
STATE_FIELDS = {"verification", "lifecycle", "missing_evidence", "corrupt_evidence"}
VERIFICATION_STATES = ("PASS", "FAIL", "INCONCLUSIVE", "INVALID")
LIFECYCLE_STATES = ("queued", "running", "completed", "cancelled", "failed", "stale", "superseded")
ATTEMPT_FIELDS = {"pass", "fail", "inconclusive", "invalid", *LIFECYCLE_STATES[3:]}
RECORD_FIELDS = {"path", "kind", "sha256"}

EXPECTED_SOURCE = {
    "repository": "https://github.com/drwbkr1/incidentseal.git",
    "branch": "main",
    "checkpoint": "checkpoint-is-0004",
    "tag_object": "60b467a7970a6fb6b5e80dcdc4dd283ab80b0acf",
    "peeled_commit": "25328dacef4d9283090bed809db75b33f613829b",
    "tree": "b03947a405f670a0ed41f0ec1544722fdbe69d20",
}
EXPECTED_RECORDS = (
    ("contracts/IS-0004.json", "contract"),
    ("records/evaluations/IS-0004-U06-integrated-recovery-implementation.json", "evaluation"),
    ("records/evaluations/IS-0004-U07-public-checkpoint.json", "evaluation"),
    ("records/surface-receipts/IS-0004-U06-public-integrated-recovery-implementation-replay.json", "surface-receipt"),
    ("records/surface-receipts/IS-0004-checkpoint-marker.json", "surface-receipt"),
    ("records/surface-receipts/IS-0004-public-checkpoint.json", "surface-receipt"),
    ("requirements/integrated-recovery-implementation.lock.json", "lock"),
)
EXPECTED_EXITS = (
    "EXIT-BACKUP-RESTORE", "EXIT-IDEMPOTENT-EVENTS", "EXIT-INDEPENDENT-VERIFIER",
    "EXIT-INTERRUPTION-RECOVERY", "EXIT-PORTABLE-RECEIPTS", "EXIT-PUBLIC-CHECKPOINT",
    "EXIT-REAL-RECOVERY", "EXIT-RECEIPT-CONTRACT",
)
EXPECTED_NON_CLAIMS = (
    "Dashboard projection is not approval authority.",
    "No repository workflow was executed.",
    "No software release or registry publication is claimed.",
    "This contract does not prove the dashboard implementation or rendered surface.",
)

CORPUS_FIELDS = {
    "schema_version", "corpus_id", "created_at_utc", "repetitions", "scenarios",
    "evaluation", "verification_verdict", "corpus_digest",
}
SCENARIO_FIELDS = {
    "id", "kind", "lifecycle", "run_verdict", "observation_verdict", "exit_code",
    "evidence_condition", "claim_allowed", "rendered_label", "required_sections",
}
EVALUATION_FIELDS = {
    "rendered_viewports", "keyboard", "contrast", "external_requests", "write_requests",
    "false_pass_limit", "false_release_claim_limit", "metrics",
}
EXPECTED_SCENARIOS = (
    ("dashboard-success", "success", "completed", "PASS", "PASS", 0, "exact", True, "Verified"),
    ("dashboard-product-failure", "product-failure", "completed", "FAIL", "FAIL", 10, "exact", False, "Product failure"),
    ("dashboard-invalid-input", "invalid-input", None, None, "INVALID", 12, "rejected", False, "Invalid input"),
    ("dashboard-missing-evidence", "missing-evidence", "completed", "PASS", "INCONCLUSIVE", 11, "missing", False, "Missing evidence"),
    ("dashboard-policy-attack", "policy-attack", None, None, "INVALID", 12, "rejected", False, "Policy attack rejected"),
    ("dashboard-isolation-attack", "isolation-attack", None, None, "INVALID", 12, "rejected", False, "Isolation attack rejected"),
    ("dashboard-corrupt-receipt", "corrupt-receipt", "completed", "PASS", "FAIL", 10, "corrupt", False, "Corrupt receipt"),
    ("dashboard-crash", "crash", "failed", None, None, 21, "interrupted", False, "Dashboard interrupted"),
    ("dashboard-recovery", "recovery", "completed", None, "PASS", 0, "recovered", False, "Recovered evidence view"),
)
EXPECTED_METRICS = (
    "case_correctness", "projection_latency_ms", "render_latency_ms",
    "peak_process_memory_bytes", "response_bytes", "request_failures",
    "source_record_coverage", "claim_calibration",
)
ALLOWED_SECTIONS = {
    "checkpoint", "state", "identity", "evidence", "authority", "custody", "recovery",
    "non-claims", "next-safe-action",
}


class DashboardContractError(ValueError):
    """Stable fail-closed dashboard contract rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise DashboardContractError(code, message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_DASHBOARD_SCHEMA", f"{label} fields differ")
    return value


def _counts(value: Any, keys: tuple[str, ...] | set[str], label: str) -> dict[str, int]:
    expected = set(keys)
    item = _exact(value, expected, label)
    if any(not isinstance(item[key], int) or isinstance(item[key], bool) or item[key] < 0 for key in expected):
        _reject("IS_DASHBOARD_STATE", f"{label} counts differ")
    return item


def _content_digest(value: dict[str, Any], field: str) -> str:
    payload = {key: item for key, item in value.items() if key != field}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def snapshot_digest(value: dict[str, Any]) -> str:
    return _content_digest(value, "snapshot_digest")


def corpus_digest(value: dict[str, Any]) -> str:
    return _content_digest(value, "corpus_digest")


def _safe_record_path(root: Path, relative: str) -> Path:
    if SAFE_PATH_RE.fullmatch(relative) is None or ".." in Path(relative).parts or "\\" in relative:
        _reject("IS_DASHBOARD_SOURCE", f"unsafe source record path: {relative}")
    root_resolved = root.resolve()
    resolved = (root_resolved / relative).resolve()
    if root_resolved not in resolved.parents:
        _reject("IS_DASHBOARD_SOURCE", f"source record escaped repository: {relative}")
    return resolved


def validate_snapshot(value: Any, root: Path) -> dict[str, Any]:
    """Validate one exact, source-bound, read-only checkpoint projection."""

    snapshot = _exact(value, SNAPSHOT_FIELDS, "snapshot")
    if snapshot["schema_version"] != "incidentseal-dashboard-snapshot/v1" or snapshot["snapshot_id"] != "IS-DASHBOARD-SNAPSHOT-0001":
        _reject("IS_DASHBOARD_SCHEMA", "snapshot identity differs")
    if not isinstance(snapshot["generated_at_utc"], str) or TIME_RE.fullmatch(snapshot["generated_at_utc"]) is None:
        _reject("IS_DASHBOARD_SCHEMA", "snapshot timestamp differs")

    source = _exact(snapshot["source"], SOURCE_FIELDS, "source")
    if source != EXPECTED_SOURCE or any(COMMIT_RE.fullmatch(source[key]) is None for key in ("tag_object", "peeled_commit", "tree")):
        _reject("IS_DASHBOARD_IDENTITY", "checkpoint source identity differs")

    authority = _exact(snapshot["authority"], AUTHORITY_FIELDS, "authority")
    if authority != {
        "approval_status": "MISSING", "approved_workflow": False,
        "workflow_executed": False, "dashboard_creates_authority": False,
    }:
        _reject("IS_DASHBOARD_AUTHORITY", "dashboard authority differs")

    trust = _exact(snapshot["trust_boundary"], TRUST_FIELDS, "trust boundary")
    expected_trust = {
        "read_only": True, "bind_host": "127.0.0.1", "allowed_methods": ["GET", "HEAD"],
        "docker_access": False, "approval_write_access": False, "repository_write_access": False,
        "external_network": False, "remote_assets": False, "analytics": False, "telemetry": False,
    }
    if trust != expected_trust:
        _reject("IS_DASHBOARD_CUSTODY", "dashboard trust boundary differs")

    exits = snapshot["exits"]
    if not isinstance(exits, list) or tuple(item.get("id") for item in exits if isinstance(item, dict)) != EXPECTED_EXITS:
        _reject("IS_DASHBOARD_STATE", "checkpoint exits differ")
    record_paths = {path for path, _ in EXPECTED_RECORDS}
    for value_exit in exits:
        item = _exact(value_exit, EXIT_FIELDS, "exit")
        evidence = item["evidence"]
        if item["status"] != "pass" or not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            _reject("IS_DASHBOARD_STATE", f"exit state differs: {item['id']}")
        if any(path not in record_paths for path in evidence):
            _reject("IS_DASHBOARD_SOURCE", f"exit evidence is not source-bound: {item['id']}")

    states = _exact(snapshot["states"], STATE_FIELDS, "states")
    _counts(states["verification"], VERIFICATION_STATES, "verification states")
    _counts(states["lifecycle"], LIFECYCLE_STATES, "lifecycle states")
    if any(not isinstance(states[key], int) or isinstance(states[key], bool) or states[key] < 0 for key in ("missing_evidence", "corrupt_evidence")):
        _reject("IS_DASHBOARD_STATE", "missing and corrupt evidence counts differ")
    _counts(snapshot["retained_attempts"], ATTEMPT_FIELDS, "retained attempts")

    records = snapshot["source_records"]
    if not isinstance(records, list) or len(records) != len(EXPECTED_RECORDS):
        _reject("IS_DASHBOARD_SOURCE", "source record set differs")
    observed_records: list[tuple[str, str]] = []
    for value_record in records:
        record = _exact(value_record, RECORD_FIELDS, "source record")
        path = record["path"]
        observed_records.append((path, record["kind"]))
        if not isinstance(record["sha256"], str) or SHA_RE.fullmatch(record["sha256"]) is None:
            _reject("IS_DASHBOARD_SOURCE", f"source digest differs: {path}")
        source_path = _safe_record_path(root, path)
        if not source_path.is_file():
            _reject("IS_DASHBOARD_SOURCE", f"source record is missing: {path}")
        actual = "sha256:" + hashlib.sha256(source_path.read_bytes()).hexdigest()
        if record["sha256"] != actual:
            _reject("IS_DASHBOARD_SOURCE", f"source record drift: {path}")
    if tuple(observed_records) != EXPECTED_RECORDS:
        _reject("IS_DASHBOARD_SOURCE", "source record order or kind differs")

    if tuple(snapshot["non_claims"]) != EXPECTED_NON_CLAIMS:
        _reject("IS_DASHBOARD_AUTHORITY", "dashboard non-claims differ")
    if snapshot["verification_verdict"] != "PASS":
        _reject("IS_DASHBOARD_STATE", "verified checkpoint snapshot verdict differs")
    if not isinstance(snapshot["snapshot_digest"], str) or SHA_RE.fullmatch(snapshot["snapshot_digest"]) is None:
        _reject("IS_DASHBOARD_SCHEMA", "snapshot digest is not lowercase SHA-256")
    if snapshot["snapshot_digest"] != snapshot_digest(snapshot):
        _reject("IS_DASHBOARD_DIGEST", "snapshot digest differs")
    return snapshot


def validate_corpus(value: Any) -> dict[str, Any]:
    """Validate the exact nine-state adversarial dashboard evaluation corpus."""

    corpus = _exact(value, CORPUS_FIELDS, "corpus")
    if corpus["schema_version"] != "incidentseal-dashboard-scenario-corpus/v1" or corpus["corpus_id"] != "IS5-DASHBOARD-CORPUS-001":
        _reject("IS_DASHBOARD_SCHEMA", "corpus identity differs")
    if not isinstance(corpus["created_at_utc"], str) or TIME_RE.fullmatch(corpus["created_at_utc"]) is None:
        _reject("IS_DASHBOARD_SCHEMA", "corpus timestamp differs")
    if corpus["repetitions"] != 3:
        _reject("IS_DASHBOARD_REPEATABILITY", "the full corpus must repeat exactly three times")
    scenarios = corpus["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(EXPECTED_SCENARIOS):
        _reject("IS_DASHBOARD_SCENARIO", "scenario count differs")
    for scenario, expected in zip(scenarios, EXPECTED_SCENARIOS, strict=True):
        item = _exact(scenario, SCENARIO_FIELDS, "scenario")
        observed = (
            item["id"], item["kind"], item["lifecycle"], item["run_verdict"],
            item["observation_verdict"], item["exit_code"], item["evidence_condition"],
            item["claim_allowed"], item["rendered_label"],
        )
        if observed != expected:
            _reject("IS_DASHBOARD_SCENARIO", f"scenario semantics differ: {expected[0]}")
        sections = item["required_sections"]
        if not isinstance(sections, list) or len(sections) < 3 or len(sections) != len(set(sections)) or any(section not in ALLOWED_SECTIONS for section in sections):
            _reject("IS_DASHBOARD_SCENARIO", f"scenario sections differ: {expected[0]}")
    evaluation = _exact(corpus["evaluation"], EVALUATION_FIELDS, "evaluation")
    if evaluation != {
        "rendered_viewports": ["1440x900", "390x844"], "keyboard": True, "contrast": True,
        "external_requests": 0, "write_requests": 0, "false_pass_limit": 0,
        "false_release_claim_limit": 0, "metrics": list(EXPECTED_METRICS),
    }:
        _reject("IS_DASHBOARD_EVALUATION", "evaluation gates differ")
    if corpus["verification_verdict"] != "PASS":
        _reject("IS_DASHBOARD_SCENARIO", "corpus contract verdict differs")
    if not isinstance(corpus["corpus_digest"], str) or SHA_RE.fullmatch(corpus["corpus_digest"]) is None:
        _reject("IS_DASHBOARD_SCHEMA", "corpus digest is not lowercase SHA-256")
    if corpus["corpus_digest"] != corpus_digest(corpus):
        _reject("IS_DASHBOARD_DIGEST", "corpus digest differs")
    return corpus
