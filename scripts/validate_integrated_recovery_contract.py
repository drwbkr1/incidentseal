#!/usr/bin/env python3
"""Validate the exact dependency-free integrated receipt and recovery contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.integrated_recovery import IntegratedRecoveryError, validate_matrix  # noqa: E402


LOCK = ROOT / "requirements" / "integrated-recovery-contract.lock.json"
MATRIX = ROOT / "fixtures" / "integrated-recovery" / "matrix.valid.json"
MUTATIONS = ROOT / "fixtures" / "integrated-recovery" / "mutations.json"

EXPECTED_PATHS = (
    "docs/decisions/ADR-0009-host-owned-integrated-recovery-matrix.md",
    "docs/integrated-recovery-contract.md",
    "docs/integrated-recovery-mutation-plan.md",
    "fixtures/integrated-recovery/matrix.invalid.minimal.json",
    "fixtures/integrated-recovery/matrix.valid.json",
    "fixtures/integrated-recovery/mutations.json",
    "requirements/meta-validation.lock",
    "schemas/integrated-recovery-matrix-v1.schema.json",
    "scripts/run_integrated_recovery_meta_validation.py",
    "scripts/test_integrated_recovery_contract_mutations.py",
    "scripts/validate_integrated_recovery_contract.py",
    "scripts/validate_integrated_recovery_schema_meta.py",
    "src/incidentseal/integrated_recovery.py",
    "src/incidentseal/manifest.py",
    "tests/test_integrated_recovery.py",
)

EXPECTED_BINDINGS = {
    "topology_runtime_lock": "requirements/topology-runtime.lock.json",
    "receipt_implementation_lock": "requirements/receipt-implementation.lock.json",
    "event_journal_implementation_lock": "requirements/event-journal-implementation.lock.json",
    "recovery_implementation_lock": "requirements/recovery-implementation.lock.json",
    "backup_restore_implementation_lock": "requirements/backup-restore-implementation.lock.json",
    "protected_volume_lock": "requirements/retained-runtime-volumes.lock.json",
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_lock() -> str:
    lock = load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-integrated-recovery-contract-lock/v1":
        raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", "integrated recovery lock version differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", "integrated recovery lock scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", f"integrated recovery lock drift: {item.get('path')}")
    for field, relative in EXPECTED_BINDINGS.items():
        if lock.get(field) != {"path": relative, "sha256": digest(ROOT / relative)}:
            raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", f"integrated recovery {field} differs")
    if lock.get("runtime_dependencies") != [] or lock.get("runtime_started") is not False:
        raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", "contract validation gained runtime")
    return digest(LOCK)


def validate() -> dict[str, Any]:
    lock_digest = validate_lock()
    matrix = validate_matrix(load(MATRIX))
    mutations = load(MUTATIONS)
    if not isinstance(mutations, dict) or mutations.get("schema_version") != "incidentseal-integrated-recovery-mutations/v1":
        raise IntegratedRecoveryError("IS_INTEGRATED_LOCK", "integrated mutation manifest differs")
    expected_count = len(mutations.get("mutations", []))
    return {
        "schema_version": "incidentseal-integrated-recovery-contract-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": lock_digest,
        "matrix_digest": matrix["matrix_digest"],
        "case_count": len(matrix["cases"]),
        "stage_count": len(matrix["composition"]["stage_order"]),
        "command_count": len(matrix["composition"]["commands"]),
        "repetitions": matrix["composition"]["repetitions"],
        "mutation_count": expected_count,
        "runtime_started": False,
        "third_party_dependencies": 0,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, IntegratedRecoveryError) else "IS_INTEGRATED_INTERNAL"
        print(json.dumps({"schema_version":"incidentseal-integrated-recovery-contract-validation/v1","verification_verdict":"INVALID","error":{"code":code,"message":str(error)}}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
