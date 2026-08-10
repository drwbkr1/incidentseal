"""Dependency-free contract for the repeated integrated receipt and recovery matrix."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .manifest import canonical_bytes


TIME_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

MATRIX_FIELDS = {
    "schema_version", "matrix_id", "created_at_utc", "authority", "composition",
    "cases", "cross_cycle", "custody", "verification_verdict", "matrix_digest",
}
AUTHORITY_FIELDS = {"mode", "approved_workflow_required", "workflow_executed", "host_cli_owns_docker"}
COMPOSITION_FIELDS = {"repetitions", "stage_order", "commands", "arbitrary_arguments", "stage_isolation"}
CASE_FIELDS = {
    "id", "surface", "expected_lifecycle", "expected_run_verdict",
    "expected_observation_verdict", "expected_exit_code", "repetitions",
}
CROSS_FIELDS = {
    "same_exact_images", "same_contract_digest", "same_semantic_receipts",
    "same_journal_streams", "same_recovery_decisions", "archive_identity_mode",
    "same_normalized_toc", "same_restored_state", "same_negative_privileges",
    "protected_volumes_unchanged", "teardown_between_stages", "teardown_after_cycle",
    "comparison_excludes",
}
CUSTODY_FIELDS = {
    "docker_socket_in_containers", "container_secrets", "broad_host_mounts",
    "external_runtime_network", "protected_volumes_mounted", "temporary_custody",
    "temporary_custody_removed", "disposable_only",
}

STAGE_ORDER = [
    "receipt-state-matrix", "reliability-probe", "journal-probe", "recovery-probe",
    "backup-restore-probe",
]
COMMANDS = [
    "receipt.materialize", "receipt.verify", "topology.reliability-probe",
    "topology.journal-probe", "topology.recovery-probe", "topology.backup-restore-probe",
]
COMPARISON_EXCLUDES = [
    "archive_digest", "backup_id", "container_id", "created_at_utc", "invocation_id",
    "receipt_digest",
]

# id, surface, lifecycle, run verdict, observation verdict, process exit
EXPECTED_CASES = [
    ("receipt-exact-identity", "receipt", None, None, "PASS", 0),
    ("receipt-unbound-identity", "receipt", None, None, "INCONCLUSIVE", 11),
    ("receipt-missing-artifact", "receipt", None, None, "INCONCLUSIVE", 11),
    ("receipt-corrupt-artifact", "receipt", None, None, "FAIL", 10),
    ("receipt-invalid-identity", "receipt", None, None, "INVALID", 12),
    ("reliability-completed-pass", "reliability", "completed", "PASS", "PASS", 0),
    ("reliability-completed-fail", "reliability", "completed", "FAIL", "FAIL", 10),
    ("reliability-malformed-input", "reliability", None, None, "INVALID", 12),
    ("reliability-database-outage", "reliability", "failed", None, None, 21),
    ("reliability-host-cancelled", "reliability", "cancelled", None, None, 20),
    ("journal-stale", "journal", "stale", None, None, 22),
    ("journal-superseded", "journal", "superseded", None, None, 23),
    ("recovery-safe-replay", "recovery", "completed", None, "PASS", 0),
    ("recovery-ambiguous-effects", "recovery", "running", None, "INCONCLUSIVE", 11),
    ("recovery-conflicting-effects", "recovery", "running", None, "FAIL", 21),
    ("recovery-authority-stale", "recovery", "stale", None, "PASS", 22),
    ("recovery-concurrent-holder", "recovery", "running", None, "INCONCLUSIVE", 11),
    ("backup-restore-complete", "backup_restore", "completed", None, "PASS", 0),
    ("backup-restore-negative-privileges", "backup_restore", "completed", None, "PASS", 0),
    ("backup-restore-teardown", "backup_restore", "completed", None, "PASS", 0),
]


class IntegratedRecoveryError(ValueError):
    """Stable fail-closed integrated-matrix contract rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise IntegratedRecoveryError(code, message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_INTEGRATED_SCHEMA", f"{label} fields differ")
    return value


def matrix_digest(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "matrix_digest"}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validate_matrix(value: Any) -> dict[str, Any]:
    """Validate the exact repeated, state-separated, host-owned matrix contract."""

    matrix = _exact(value, MATRIX_FIELDS, "matrix")
    if matrix["schema_version"] != "incidentseal-integrated-recovery-matrix/v1":
        _reject("IS_INTEGRATED_SCHEMA", "matrix schema version differs")
    if matrix["matrix_id"] != "IS4-U06-INTEGRATED-RECOVERY-001":
        _reject("IS_INTEGRATED_SCHEMA", "matrix identity differs")
    if not isinstance(matrix["created_at_utc"], str) or TIME_RE.fullmatch(matrix["created_at_utc"]) is None:
        _reject("IS_INTEGRATED_SCHEMA", "matrix timestamp differs")

    authority = _exact(matrix["authority"], AUTHORITY_FIELDS, "authority")
    if authority != {
        "mode": "platform-validation",
        "approved_workflow_required": False,
        "workflow_executed": False,
        "host_cli_owns_docker": True,
    }:
        _reject("IS_INTEGRATED_AUTHORITY", "integrated authority differs")

    composition = _exact(matrix["composition"], COMPOSITION_FIELDS, "composition")
    if composition["repetitions"] != 2:
        _reject("IS_INTEGRATED_REPEATABILITY", "the full matrix must repeat exactly twice")
    if composition["stage_order"] != STAGE_ORDER or composition["commands"] != COMMANDS:
        _reject("IS_INTEGRATED_COMPOSITION", "stage or command composition differs")
    if composition["arbitrary_arguments"] is not False:
        _reject("IS_INTEGRATED_AUTHORITY", "arbitrary integrated arguments became available")
    if composition["stage_isolation"] is not True:
        _reject("IS_INTEGRATED_CUSTODY", "stage isolation is absent")

    cases = matrix["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASES):
        _reject("IS_INTEGRATED_STATE", "the exact state matrix differs")
    for case, expected in zip(cases, EXPECTED_CASES, strict=True):
        item = _exact(case, CASE_FIELDS, "case")
        observed = (
            item["id"], item["surface"], item["expected_lifecycle"],
            item["expected_run_verdict"], item["expected_observation_verdict"],
            item["expected_exit_code"],
        )
        if observed != expected:
            _reject("IS_INTEGRATED_STATE", f"state expectation differs for {expected[0]}")
        if item["repetitions"] != 2:
            _reject("IS_INTEGRATED_REPEATABILITY", f"case repetition differs for {expected[0]}")

    cross = _exact(matrix["cross_cycle"], CROSS_FIELDS, "cross-cycle")
    repeat_true = (
        "same_exact_images", "same_contract_digest", "same_semantic_receipts",
        "same_journal_streams", "same_recovery_decisions", "same_normalized_toc",
        "same_restored_state", "same_negative_privileges",
    )
    if any(cross[field] is not True for field in repeat_true):
        _reject("IS_INTEGRATED_REPEATABILITY", "cross-cycle semantic identity differs")
    if cross["archive_identity_mode"] != "per-receipt-raw-plus-stable-normalized-toc":
        _reject("IS_INTEGRATED_REPEATABILITY", "archive identity comparison differs")
    if cross["comparison_excludes"] != COMPARISON_EXCLUDES:
        _reject("IS_INTEGRATED_REPEATABILITY", "dynamic comparison exclusions differ")
    if cross["protected_volumes_unchanged"] is not True:
        _reject("IS_INTEGRATED_CUSTODY", "protected volume identity may change")
    if cross["teardown_between_stages"] is not True or cross["teardown_after_cycle"] is not True:
        _reject("IS_INTEGRATED_CUSTODY", "integrated teardown is not mandatory")

    custody = _exact(matrix["custody"], CUSTODY_FIELDS, "custody")
    if any(custody[field] is not False for field in (
        "docker_socket_in_containers", "container_secrets", "broad_host_mounts",
        "external_runtime_network", "protected_volumes_mounted",
    )):
        _reject("IS_INTEGRATED_CUSTODY", "container or protected custody broadened")
    if custody["temporary_custody"] != "host-temp-outside-repository-and-onedrive":
        _reject("IS_INTEGRATED_CUSTODY", "temporary custody differs")
    if custody["temporary_custody_removed"] is not True or custody["disposable_only"] is not True:
        _reject("IS_INTEGRATED_CUSTODY", "disposable custody may remain")

    if matrix["verification_verdict"] != "PASS":
        _reject("IS_INTEGRATED_STATE", "matrix contract verdict differs")
    if not isinstance(matrix["matrix_digest"], str) or SHA_RE.fullmatch(matrix["matrix_digest"]) is None:
        _reject("IS_INTEGRATED_SCHEMA", "matrix digest is not lowercase SHA-256")
    if matrix["matrix_digest"] != matrix_digest(matrix):
        _reject("IS_INTEGRATED_IDENTITY", "matrix digest differs")
    return matrix
