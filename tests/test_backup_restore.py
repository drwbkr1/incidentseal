from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.backup_restore import BackupRestoreError, receipt_digest, validate_receipt


class BackupRestoreContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads((ROOT / "fixtures" / "backup-restore" / "vectors.json").read_text(encoding="utf-8"))["golden"]

    def changed(self) -> dict:
        return deepcopy(self.golden)

    def test_golden_receipt_is_content_addressed(self) -> None:
        value = validate_receipt(self.changed())
        self.assertEqual(value["receipt_digest"], receipt_digest(value))

    def test_unknown_fields_fail_closed(self) -> None:
        value = self.changed()
        value["unexpected"] = True
        value["receipt_digest"] = receipt_digest(value)
        with self.assertRaisesRegex(BackupRestoreError, "fields differ"):
            validate_receipt(value)

    def test_restore_must_use_the_exact_archive(self) -> None:
        value = self.changed()
        value["restore"]["source_archive_digest"] = "sha256:" + "7" * 64
        value["receipt_digest"] = receipt_digest(value)
        with self.assertRaises(BackupRestoreError) as raised:
            validate_receipt(value)
        self.assertEqual(raised.exception.code, "IS_BACKUP_ARCHIVE")

    def test_roles_are_measured_and_hardened_not_restored_from_dump(self) -> None:
        value = self.changed()
        value["roles"]["items"][1]["superuser"] = True
        value["receipt_digest"] = receipt_digest(value)
        with self.assertRaises(BackupRestoreError) as raised:
            validate_receipt(value)
        self.assertEqual(raised.exception.code, "IS_BACKUP_ROLE")

    def test_restored_state_must_equal_the_source_state(self) -> None:
        value = self.changed()
        value["restore"]["journal_digest"] = "sha256:" + "8" * 64
        value["receipt_digest"] = receipt_digest(value)
        with self.assertRaises(BackupRestoreError) as raised:
            validate_receipt(value)
        self.assertEqual(raised.exception.code, "IS_BACKUP_EQUIVALENCE")

    def test_protected_custody_and_teardown_are_mandatory(self) -> None:
        for field in ("protected_volumes_unchanged", "disposable_teardown"):
            value = self.changed()
            value["restore"][field] = False
            value["receipt_digest"] = receipt_digest(value)
            with self.assertRaises(BackupRestoreError) as raised:
                validate_receipt(value)
            self.assertEqual(raised.exception.code, "IS_BACKUP_CUSTODY")


if __name__ == "__main__":
    unittest.main()
