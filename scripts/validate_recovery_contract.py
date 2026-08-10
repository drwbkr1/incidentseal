#!/usr/bin/env python3
"""Validate the frozen interruption-recovery contract without runtime or dependencies."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import ManifestError, canonical_bytes, strict_load_bytes  # noqa: E402
from incidentseal.recovery import RecoveryError, decide_recovery, validate_decision  # noqa: E402


LOCK = ROOT / "requirements" / "recovery-contract.lock.json"
VECTORS = ROOT / "fixtures" / "recovery" / "vectors.json"
EXPECTED_PATHS = (
    "docs/decisions/ADR-0007-fenced-interruption-recovery.md",
    "docs/interruption-recovery-contract.md",
    "docs/interruption-recovery-mutation-plan.md",
    "fixtures/recovery/decision.invalid.minimal.json",
    "fixtures/recovery/mutations.json",
    "fixtures/recovery/observation.invalid.minimal.json",
    "fixtures/recovery/vectors.json",
    "requirements/event-journal-contract.lock.json",
    "requirements/meta-validation.lock",
    "schemas/recovery-decision-v1.schema.json",
    "schemas/recovery-observation-v1.schema.json",
    "scripts/run_recovery_meta_validation.py",
    "scripts/test_recovery_contract_mutations.py",
    "scripts/validate_recovery_contract.py",
    "scripts/validate_recovery_schema_meta.py",
    "src/incidentseal/manifest.py",
    "src/incidentseal/recovery.py",
    "tests/test_recovery.py",
)
EXPECTED_CASES = (
    "safe-replay-before-dispatch",
    "committed-effects-continue",
    "ambiguous-effects-defer",
    "confirmed-cancellation",
    "confirmed-process-failure",
    "conflicting-effects-fail",
    "authority-drift-stale",
    "owned-orphan-stop",
    "active-owner-defer",
    "unowned-orphan-defer",
    "unsafe-replay-defer",
    "authority-unavailable-defer",
)
EXPECTED_SUMMARY_FIELDS = {
    "verification_verdict",
    "disposition",
    "reason_code",
    "process_action",
    "replay_step",
    "next_phase",
    "evidence_event_type",
    "terminal_event_type",
    "terminal_lifecycle",
    "run_verdict",
}


def load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except (OSError, ManifestError) as error:
        raise RecoveryError("IS_RECOVERY_JSON", f"could not strictly load {path.name}") from error


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RecoveryError("IS_RECOVERY_SCHEMA", f"{label} fields differ")
    return value


def validate_lock() -> str:
    lock = load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-recovery-contract-lock/v1":
        raise RecoveryError("IS_RECOVERY_LOCK", "recovery contract lock version differs")
    entries = lock.get("files")
    if not isinstance(entries, list):
        raise RecoveryError("IS_RECOVERY_LOCK", "recovery lock files are absent")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if tuple(paths) != EXPECTED_PATHS or len(paths) != len(set(paths)):
        raise RecoveryError("IS_RECOVERY_LOCK", "recovery lock path set differs")
    for entry in entries:
        if file_digest(ROOT / entry["path"]) != entry.get("sha256"):
            raise RecoveryError("IS_RECOVERY_LOCK", f"recovery lock drift: {entry['path']}")
    return file_digest(LOCK)


def decision_summary(decision: dict[str, Any]) -> dict[str, Any]:
    summary = {
        name: decision[name]
        for name in ("verification_verdict", "disposition", "reason_code", "process_action", "replay_step", "next_phase")
    }
    summary.update(decision["append"])
    return summary


def validate() -> dict[str, Any]:
    lock_digest = validate_lock()
    vectors = exact(load(VECTORS), {"schema_version", "cases"}, "vectors")
    if vectors["schema_version"] != "incidentseal-recovery-vectors/v1":
        raise RecoveryError("IS_RECOVERY_VECTOR", "recovery vector version differs")
    cases = vectors["cases"]
    if not isinstance(cases, list) or tuple(case.get("id") for case in cases if isinstance(case, dict)) != EXPECTED_CASES:
        raise RecoveryError("IS_RECOVERY_VECTOR", "recovery vector cases differ")
    observation_digests: list[str] = []
    decision_digests: list[str] = []
    verdict_counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "INVALID": 0}
    disposition_counts: dict[str, int] = {}
    terminal_plans = 0
    for case in cases:
        exact(case, {"id", "observation", "expected"}, "vector case")
        expected = exact(case["expected"], EXPECTED_SUMMARY_FIELDS, "expected summary")
        decision = decide_recovery(case["observation"])
        validate_decision(decision, case["observation"])
        if decision_summary(decision) != expected:
            raise RecoveryError("IS_RECOVERY_VECTOR", f"decision summary differs: {case['id']}")
        if decision["append"]["run_verdict"] is not None:
            raise RecoveryError("IS_RECOVERY_VERDICT", "recovery vector fabricated a run verdict")
        observation_digests.append(decision["observation_digest"])
        decision_digests.append(decision["decision_digest"])
        verdict_counts[decision["verification_verdict"]] += 1
        disposition_counts[decision["disposition"]] = disposition_counts.get(decision["disposition"], 0) + 1
        if decision["append"]["terminal_event_type"] is not None:
            terminal_plans += 1
    if len(set(observation_digests)) != len(cases) or len(set(decision_digests)) != len(cases):
        raise RecoveryError("IS_RECOVERY_IDENTITY", "recovery vector identities are not unique")
    return {
        "schema_version": "incidentseal-recovery-contract-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": lock_digest,
        "vector_digest": file_digest(VECTORS),
        "case_count": len(cases),
        "verdict_counts": verdict_counts,
        "disposition_counts": disposition_counts,
        "terminal_plan_count": terminal_plans,
        "safe_replay_observation_digest": observation_digests[0],
        "safe_replay_decision_digest": decision_digests[0],
        "run_verdicts": "ALL_NULL",
        "runtime_started": False,
        "third_party_dependencies": 0,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, RecoveryError) else "IS_RECOVERY_INTERNAL"
        print(json.dumps({"schema_version":"incidentseal-recovery-contract-validation/v1","verification_verdict":"INVALID","error":{"code":code,"message":str(error)}}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
