#!/usr/bin/env python3
"""Require every bounded backup/restore contract mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.backup_restore import BackupRestoreError, receipt_digest, validate_receipt  # noqa: E402


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def set_unknown(value: dict[str, Any]) -> None: value["unexpected"] = True
def set_authority(value: dict[str, Any]) -> None: value["authority"]["mode"] = "approved-workflow"
def set_source_custody(value: dict[str, Any]) -> None: value["source"]["disposable"] = False
def set_version(value: dict[str, Any]) -> None: value["source"]["postgres_version_num"] = 180005
def set_format(value: dict[str, Any]) -> None: value["backup"]["format"] = "plain-sql"
def set_writes(value: dict[str, Any]) -> None: value["backup"]["source_writes_blocked"] = False
def set_dump_argv(value: dict[str, Any]) -> None: value["backup"]["pg_dump_argv"][4] = "--privileges"
def set_fsync(value: dict[str, Any]) -> None: value["backup"]["fsync_required"] = False
def set_role_mode(value: dict[str, Any]) -> None: value["roles"]["mode"] = "restored-from-dump"
def set_runner_superuser(value: dict[str, Any]) -> None: value["roles"]["items"][1]["superuser"] = True
def set_archive(value: dict[str, Any]) -> None: value["restore"]["source_archive_digest"] = "sha256:" + "7" * 64
def set_project(value: dict[str, Any]) -> None: value["restore"]["target_project_name"] = value["source"]["project_name"]
def set_restore_argv(value: dict[str, Any]) -> None: value["restore"]["pg_restore_argv"][1] = "--verbose"
def set_schema(value: dict[str, Any]) -> None: value["restore"]["schema_digest"] = "sha256:" + "8" * 64
def set_privilege(value: dict[str, Any]) -> None: value["restore"]["negative_privileges"]["runner_journal_read"] = "allowed"
def set_protected(value: dict[str, Any]) -> None: value["restore"]["protected_volumes_unchanged"] = False
def set_teardown(value: dict[str, Any]) -> None: value["restore"]["disposable_teardown"] = False
def set_digest(value: dict[str, Any]) -> None: value["receipt_digest"] = "sha256:" + "9" * 64


MUTATORS: dict[str, Callable[[dict[str, Any]], None]] = {
    "unknown-receipt-field": set_unknown,
    "workflow-authority-smuggled": set_authority,
    "protected-source-volume": set_source_custody,
    "postgres-version-drift": set_version,
    "plain-archive-substitution": set_format,
    "concurrent-source-writes": set_writes,
    "dump-privileges-restored": set_dump_argv,
    "fsync-disabled": set_fsync,
    "roles-restored-from-dump": set_role_mode,
    "runner-promoted-superuser": set_runner_superuser,
    "restore-archive-substitution": set_archive,
    "source-project-reused": set_project,
    "restore-error-stop-removed": set_restore_argv,
    "restored-schema-drift": set_schema,
    "runner-journal-read-allowed": set_privilege,
    "protected-volume-changed": set_protected,
    "disposable-restore-retained": set_teardown,
    "receipt-digest-tampered": set_digest,
}


def main() -> int:
    golden = load(ROOT / "fixtures" / "backup-restore" / "vectors.json")["golden"]
    manifest = load(ROOT / "fixtures" / "backup-restore" / "mutations.json")
    if tuple(MUTATORS) != tuple(item["id"] for item in manifest["mutations"]):
        raise RuntimeError("backup/restore mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        value = deepcopy(golden)
        MUTATORS[item["id"]](value)
        if item["id"] != "receipt-digest-tampered":
            value["receipt_digest"] = receipt_digest(value)
        code = None
        try:
            validate_receipt(value)
        except BackupRestoreError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({"id":item["id"],"expected_error":item["expected_error"],"actual_error":code,"verification_verdict":"PASS" if passed else "FAIL"})
        if not passed:
            raise RuntimeError(f"mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({"schema_version":"incidentseal-backup-restore-mutation-results/v1","verification_verdict":"PASS","mutation_count":len(results),"mutations":results,"runtime_started":False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
