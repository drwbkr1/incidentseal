#!/usr/bin/env python3
"""Validate the frozen PostgreSQL backup and clean-restore contract without runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.backup_restore import BackupRestoreError, validate_receipt  # noqa: E402
from incidentseal.manifest import ManifestError, strict_load_bytes  # noqa: E402


LOCK = ROOT / "requirements" / "backup-restore-contract.lock.json"
VECTORS = ROOT / "fixtures" / "backup-restore" / "vectors.json"
EXPECTED_PATHS = (
    "docs/backup-restore-contract.md",
    "docs/backup-restore-mutation-plan.md",
    "docs/decisions/ADR-0008-logical-backup-clean-restore.md",
    "fixtures/backup-restore/mutations.json",
    "fixtures/backup-restore/receipt.invalid.minimal.json",
    "fixtures/backup-restore/vectors.json",
    "requirements/meta-validation.lock",
    "schemas/backup-restore-receipt-v1.schema.json",
    "scripts/run_backup_restore_meta_validation.py",
    "scripts/test_backup_restore_contract_mutations.py",
    "scripts/validate_backup_restore_contract.py",
    "scripts/validate_backup_restore_schema_meta.py",
    "src/incidentseal/backup_restore.py",
    "src/incidentseal/manifest.py",
    "tests/test_backup_restore.py",
)


def load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except (OSError, ManifestError) as error:
        raise BackupRestoreError("IS_BACKUP_JSON", f"could not strictly load {path.name}") from error


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_lock() -> str:
    lock = load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-backup-restore-contract-lock/v1":
        raise BackupRestoreError("IS_BACKUP_LOCK", "backup/restore lock version differs")
    entries = lock.get("files")
    paths = [item.get("path") for item in entries] if isinstance(entries, list) else []
    if tuple(paths) != EXPECTED_PATHS or len(paths) != len(set(paths)):
        raise BackupRestoreError("IS_BACKUP_LOCK", "backup/restore lock path set differs")
    for item in entries:
        if digest(ROOT / item["path"]) != item.get("sha256"):
            raise BackupRestoreError("IS_BACKUP_LOCK", f"backup/restore lock drift: {item['path']}")
    return digest(LOCK)


def validate() -> dict[str, Any]:
    lock_digest = validate_lock()
    vectors = load(VECTORS)
    if not isinstance(vectors, dict) or set(vectors) != {"schema_version", "golden"} or vectors["schema_version"] != "incidentseal-backup-restore-vectors/v1":
        raise BackupRestoreError("IS_BACKUP_VECTOR", "backup/restore vectors differ")
    receipt = validate_receipt(vectors["golden"])
    return {
        "schema_version":"incidentseal-backup-restore-contract-validation/v1",
        "verification_verdict":"PASS",
        "lock_digest":lock_digest,
        "vector_digest":digest(VECTORS),
        "receipt_digest":receipt["receipt_digest"],
        "archive_format":receipt["backup"]["format"],
        "role_mode":receipt["roles"]["mode"],
        "negative_privilege_checks":len(receipt["restore"]["negative_privileges"]),
        "runtime_started":False,
        "third_party_dependencies":0,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, BackupRestoreError) else "IS_BACKUP_INTERNAL"
        print(json.dumps({"schema_version":"incidentseal-backup-restore-contract-validation/v1","verification_verdict":"INVALID","error":{"code":code,"message":str(error)}}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
