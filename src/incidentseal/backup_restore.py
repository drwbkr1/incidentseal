"""Dependency-free PostgreSQL logical backup and clean-restore receipt contract."""

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
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$")

RECEIPT_FIELDS = {
    "schema_version", "backup_id", "created_at_utc", "authority", "source", "backup",
    "roles", "restore", "verification_verdict", "receipt_digest",
}
AUTHORITY_FIELDS = {"mode", "contract_digest"}
SOURCE_FIELDS = {
    "project_name", "disposable", "database_image_id", "migration_image_id",
    "postgres_version_num", "database_name", "schema_digest", "journal",
    "verification_results", "role_digest",
}
JOURNAL_FIELDS = {"run_count", "event_count", "ordered_stream_digest"}
RESULT_FIELDS = {"row_count", "rows_digest"}
BACKUP_FIELDS = {
    "format", "archive_digest", "archive_bytes", "normalized_toc_digest", "toc_entries",
    "source_writes_blocked", "pg_dump_argv", "stderr_policy", "fsync_required",
}
ROLES_FIELDS = {"mode", "roles_digest", "items"}
ROLE_FIELDS = {
    "name", "superuser", "create_db", "create_role", "replication", "bypass_rls", "login",
}
RESTORE_FIELDS = {
    "clean_target", "target_project_name", "target_volume_name", "source_archive_digest",
    "pg_restore_argv", "post_restore_migration_image_id", "exit_code", "stderr_policy",
    "schema_digest", "role_digest", "journal_digest", "verification_results_digest",
    "negative_privileges", "protected_volumes_unchanged", "disposable_teardown",
}
PRIVILEGE_FIELDS = {
    "runner_schema_create", "runner_ddl", "runner_migration_read",
    "runner_journal_read", "runner_recovery_fence_read",
}

PG_DUMP_ARGV = [
    "pg_dump", "--format=custom", "--compress=0", "--no-owner", "--no-privileges",
    "--file=/incidentseal/backup/incidentseal.dump", "--dbname=incidentseal",
]
PG_RESTORE_ARGV = [
    "pg_restore", "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges",
    "--dbname=incidentseal", "/incidentseal/backup/incidentseal.dump",
]


class BackupRestoreError(ValueError):
    """A stable fail-closed backup/restore contract rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise BackupRestoreError(code, message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject("IS_BACKUP_SCHEMA", f"{label} fields differ")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        _reject("IS_BACKUP_SCHEMA", f"{label} is not a lowercase SHA-256 digest")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= 9007199254740991:
        _reject("IS_BACKUP_SCHEMA", f"{label} is not a bounded integer")
    return value


def _receipt_digest(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "receipt_digest"}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def validate_receipt(value: Any) -> dict[str, Any]:
    """Validate one closed backup/restore receipt and every cross-surface equivalence."""

    receipt = _exact(value, RECEIPT_FIELDS, "receipt")
    if receipt["schema_version"] != "incidentseal-backup-restore-receipt/v1":
        _reject("IS_BACKUP_SCHEMA", "receipt schema version differs")
    if not isinstance(receipt["backup_id"], str) or UUID_RE.fullmatch(receipt["backup_id"]) is None:
        _reject("IS_BACKUP_SCHEMA", "backup_id is not a lowercase UUIDv4")
    if not isinstance(receipt["created_at_utc"], str) or TIME_RE.fullmatch(receipt["created_at_utc"]) is None:
        _reject("IS_BACKUP_SCHEMA", "created_at_utc is not a UTC timestamp")

    authority = _exact(receipt["authority"], AUTHORITY_FIELDS, "authority")
    if authority["mode"] != "platform-validation":
        _reject("IS_BACKUP_AUTHORITY", "backup authority is not fixed platform validation")
    _sha(authority["contract_digest"], "contract digest")

    source = _exact(receipt["source"], SOURCE_FIELDS, "source")
    if not isinstance(source["project_name"], str) or NAME_RE.fullmatch(source["project_name"]) is None:
        _reject("IS_BACKUP_SCHEMA", "source project name differs")
    if source["disposable"] is not True:
        _reject("IS_BACKUP_CUSTODY", "backup source is not disposable custody")
    for name in ("database_image_id", "migration_image_id", "schema_digest", "role_digest"):
        _sha(source[name], f"source {name}")
    if source["postgres_version_num"] != 180004 or source["database_name"] != "incidentseal":
        _reject("IS_BACKUP_SOURCE", "PostgreSQL source identity differs")
    journal = _exact(source["journal"], JOURNAL_FIELDS, "source journal")
    _integer(journal["run_count"], "journal run count", 1)
    _integer(journal["event_count"], "journal event count", 1)
    _sha(journal["ordered_stream_digest"], "journal stream digest")
    results = _exact(source["verification_results"], RESULT_FIELDS, "source verification results")
    _integer(results["row_count"], "verification result count", 1)
    _sha(results["rows_digest"], "verification result digest")

    backup = _exact(receipt["backup"], BACKUP_FIELDS, "backup")
    if backup["format"] != "postgresql-custom-v1":
        _reject("IS_BACKUP_ARCHIVE", "backup archive format differs")
    _sha(backup["archive_digest"], "archive digest")
    _integer(backup["archive_bytes"], "archive bytes", 1)
    _sha(backup["normalized_toc_digest"], "normalized TOC digest")
    _integer(backup["toc_entries"], "TOC entry count", 1)
    if backup["source_writes_blocked"] is not True:
        _reject("IS_BACKUP_SNAPSHOT", "source writes were not blocked for the evidence snapshot")
    if backup["pg_dump_argv"] != PG_DUMP_ARGV:
        _reject("IS_BACKUP_COMMAND", "pg_dump arguments differ")
    if backup["stderr_policy"] != "empty" or backup["fsync_required"] is not True:
        _reject("IS_BACKUP_DURABILITY", "backup durability or diagnostics policy differs")

    roles = _exact(receipt["roles"], ROLES_FIELDS, "roles")
    if roles["mode"] != "verified-baseline-not-restored-from-dump":
        _reject("IS_BACKUP_ROLE", "role restoration mode differs")
    if _sha(roles["roles_digest"], "roles digest") != source["role_digest"]:
        _reject("IS_BACKUP_ROLE", "source role digest differs")
    items = roles["items"]
    if not isinstance(items, list) or len(items) != 2:
        _reject("IS_BACKUP_ROLE", "exact two-role baseline is absent")
    expected_names = ("incidentseal_admin", "incidentseal_runner")
    for index, item in enumerate(items):
        role = _exact(item, ROLE_FIELDS, "role")
        if role["name"] != expected_names[index]:
            _reject("IS_BACKUP_ROLE", "role order or identity differs")
        for field in ("create_db", "create_role", "replication", "bypass_rls"):
            if role[field] is not False:
                _reject("IS_BACKUP_PRIVILEGE", f"role {field} is elevated")
        if role["login"] is not True:
            _reject("IS_BACKUP_ROLE", "required role login differs")
        if role["superuser"] is not (index == 0):
            _reject("IS_BACKUP_ROLE", "bootstrap and runner superuser separation differs")

    restore = _exact(receipt["restore"], RESTORE_FIELDS, "restore")
    if restore["clean_target"] is not True:
        _reject("IS_BACKUP_CUSTODY", "restore target is not clean")
    for name in ("target_project_name", "target_volume_name"):
        if not isinstance(restore[name], str) or NAME_RE.fullmatch(restore[name]) is None:
            _reject("IS_BACKUP_SCHEMA", f"restore {name} differs")
    if restore["target_project_name"] == source["project_name"]:
        _reject("IS_BACKUP_CUSTODY", "restore reused the source project")
    if _sha(restore["source_archive_digest"], "restore archive digest") != backup["archive_digest"]:
        _reject("IS_BACKUP_ARCHIVE", "restored archive identity differs")
    if restore["pg_restore_argv"] != PG_RESTORE_ARGV:
        _reject("IS_BACKUP_COMMAND", "pg_restore arguments differ")
    if _sha(restore["post_restore_migration_image_id"], "post-restore migration image") != source["migration_image_id"]:
        _reject("IS_BACKUP_ROLE", "post-restore role hardening image differs")
    if restore["exit_code"] != 0 or restore["stderr_policy"] != "empty":
        _reject("IS_BACKUP_RESTORE", "restore did not complete without diagnostics")
    equivalence = {
        "schema_digest": source["schema_digest"],
        "role_digest": source["role_digest"],
        "journal_digest": journal["ordered_stream_digest"],
        "verification_results_digest": results["rows_digest"],
    }
    for name, expected in equivalence.items():
        if _sha(restore[name], f"restored {name}") != expected:
            _reject("IS_BACKUP_EQUIVALENCE", f"restored {name} differs")
    privileges = _exact(restore["negative_privileges"], PRIVILEGE_FIELDS, "negative privileges")
    if any(value != "denied" for value in privileges.values()):
        _reject("IS_BACKUP_PRIVILEGE", "restored runner privilege boundary differs")
    if restore["protected_volumes_unchanged"] is not True or restore["disposable_teardown"] is not True:
        _reject("IS_BACKUP_CUSTODY", "restore custody or teardown differs")

    if receipt["verification_verdict"] != "PASS":
        _reject("IS_BACKUP_VERDICT", "verified exact restore is not PASS")
    expected_digest = _receipt_digest(receipt)
    if _sha(receipt["receipt_digest"], "receipt digest") != expected_digest:
        _reject("IS_BACKUP_IDENTITY", "receipt digest differs")
    return receipt


def receipt_digest(value: dict[str, Any]) -> str:
    """Return the content identity for a receipt before its digest is inserted."""

    return _receipt_digest(value)
