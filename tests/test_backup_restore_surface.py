from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

from incidentseal.backup_restore_surface import (  # noqa: E402
    SOURCE_PROJECT,
    SOURCE_VOLUME,
    TARGET_PROJECT,
    TARGET_VOLUME,
    _migration_notice_count,
    _normalize_toc,
    _safe_custody,
)
from incidentseal.cli import UsageError, _parse  # noqa: E402
from incidentseal.topology import TopologyError  # noqa: E402


VALID_TOC = """;
; variable archive header
215; 1259 100 TABLE public verification_results incidentseal_admin
216; 1259 101 TABLE public incidentseal_run_events incidentseal_admin
217; 0 100 TABLE DATA public verification_results incidentseal_admin
218; 0 101 TABLE DATA public incidentseal_run_events incidentseal_admin
219; 1255 102 FUNCTION public incidentseal_append_event(bytea, bytea) incidentseal_admin
"""


class BackupRestoreSurfaceTests(unittest.TestCase):
    def test_fixed_projects_and_volumes_are_distinct(self) -> None:
        self.assertEqual(SOURCE_PROJECT, "incidentseal-backup-source")
        self.assertEqual(TARGET_PROJECT, "incidentseal-restore-target")
        self.assertNotEqual(SOURCE_PROJECT, TARGET_PROJECT)
        self.assertNotEqual(SOURCE_VOLUME, TARGET_VOLUME)

    def test_toc_normalization_removes_comments_and_is_stable(self) -> None:
        normalized = _normalize_toc(VALID_TOC)
        self.assertNotIn(b"variable archive header", normalized)
        self.assertEqual(normalized.count(b"\n"), 5)
        self.assertEqual(normalized, _normalize_toc(VALID_TOC.replace(" ", "  ")))

    def test_toc_rejects_acl_and_missing_core_objects(self) -> None:
        with self.assertRaises(TopologyError) as acl:
            _normalize_toc(VALID_TOC + "220; 0 0 ACL public TABLE verification_results incidentseal_admin\n")
        self.assertEqual(acl.exception.code, "IS_BACKUP_ARCHIVE")
        with self.assertRaises(TopologyError):
            _normalize_toc("215; 1259 100 TABLE public verification_results incidentseal_admin\n")

    def test_repository_custody_is_rejected(self) -> None:
        with self.assertRaises(TopologyError) as raised:
            _safe_custody(ROOT)
        self.assertEqual(raised.exception.code, "IS_BACKUP_CUSTODY")

    def test_migration_diagnostics_are_narrowly_classified(self) -> None:
        self.assertEqual(_migration_notice_count(""), 0)
        self.assertEqual(_migration_notice_count('NOTICE: relation "verification_results" already exists, skipping\n'), 1)
        self.assertEqual(
            _migration_notice_count('psql:/opt/incidentseal/migrations/001-schema.sql:25: NOTICE:  relation "verification_results" already exists, skipping\n'),
            1,
        )
        with self.assertRaises(TopologyError):
            _migration_notice_count("WARNING: unexpected migration warning\n")

    def test_cli_surface_is_argument_free_beyond_fixed_mode(self) -> None:
        request = _parse(["topology", "backup-restore-probe", "--mode", "platform-validation", "--json"])
        self.assertEqual(request.command, "topology.backup-restore-probe")
        with tempfile.TemporaryDirectory(prefix="incidentseal-backup-cli-test-") as temporary:
            with self.assertRaises(UsageError):
                _parse([
                    "topology", "backup-restore-probe", "--mode", "platform-validation",
                    "--source-root", temporary, "--json",
                ])


if __name__ == "__main__":
    unittest.main()
