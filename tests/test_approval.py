from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.approval import (  # noqa: E402
    ApprovalStore,
    default_approval_root,
    manifest_relative_path,
    repository_key,
)
from incidentseal.manifest import load_manifest  # noqa: E402


FIXTURES = ROOT / "fixtures" / "contracts"
NOW = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC)


class ApprovalStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="incidentseal-u03-")
        self.base = Path(self.temporary.name)
        self.repository_root = self.base / "repository"
        self.repository_root.mkdir()
        (self.repository_root / ".git").mkdir()
        self.manifest_path = self.repository_root / "incidentseal.workflow.json"
        self.manifest_path.write_bytes((FIXTURES / "workflow.valid.minimal.json").read_bytes())
        self.document = load_manifest(self.manifest_path)
        self.approval_root = self.base / "operator-state" / "approvals" / "v1"
        self.approval_path = (
            self.approval_root
            / repository_key(self.document.value["repository"]["remote"])
            / f"{self.document.value['workflow_id']}.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def approval(self) -> dict:
        value = json.loads((FIXTURES / "approval.valid.json").read_text(encoding="utf-8"))
        value["manifest_path"] = "incidentseal.workflow.json"
        return value

    def write_approval(self, value: dict | bytes) -> None:
        self.approval_path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
        self.approval_path.write_bytes(raw)

    def inspect(self):
        relative = manifest_relative_path(self.document, self.repository_root)
        self.assertEqual("incidentseal.workflow.json", relative)
        return ApprovalStore(self.approval_root, self.repository_root).inspect(
            self.document,
            relative,
            now=NOW,
        )

    def test_missing_does_not_create_store(self) -> None:
        result = self.inspect()
        self.assertEqual("MISSING", result.status)
        self.assertFalse(self.approval_root.exists())

    def test_exact_approval_matches(self) -> None:
        self.write_approval(self.approval())
        result = self.inspect()
        self.assertEqual("MATCH", result.status)
        self.assertTrue(result.approved)
        self.assertEqual(self.document.digest, result.approved_digest)
        self.assertEqual(1, len(result.evidence()))

    @unittest.skipUnless(os.name == "nt", "Windows trusted-path probe")
    def test_windows_process_environment_cannot_redirect_or_shadow_custody_tools(self) -> None:
        actual_root = default_approval_root()
        self.write_approval(self.approval())
        with patch.dict(
            os.environ,
            {"LOCALAPPDATA": str(self.repository_root), "PATH": str(self.repository_root)},
            clear=False,
        ):
            self.assertEqual(actual_root, default_approval_root())
            self.assertEqual("MATCH", self.inspect().status)

    def test_digest_path_and_remote_changes_mismatch(self) -> None:
        mutations = {
            "manifest_digest": "sha256:" + "9" * 64,
            "manifest_path": "other.json",
            "repository_remote": "https://github.com/example/other.git",
        }
        for field, changed in mutations.items():
            with self.subTest(field=field):
                value = self.approval()
                value[field] = changed
                self.write_approval(value)
                result = self.inspect()
                self.assertEqual("MISMATCH", result.status)
                self.assertIn(field, result.differences)

    def test_expired_exact_approval_is_distinct(self) -> None:
        value = self.approval()
        value["expires_at_utc"] = "2026-08-09T01:00:00Z"
        self.write_approval(value)
        result = self.inspect()
        self.assertEqual("EXPIRED", result.status)
        self.assertEqual(("expires_at_utc",), result.differences)

    def test_invalid_record_is_distinct(self) -> None:
        self.write_approval(b'{"schema_version":"wrong"}\n')
        result = self.inspect()
        self.assertEqual("INVALID", result.status)
        self.assertEqual("IS_APPROVAL_INVALID", result.error_code)

    def test_repository_contained_store_is_invalid(self) -> None:
        root = self.repository_root / ".incidentseal" / "approvals"
        result = ApprovalStore(root, self.repository_root).inspect(
            self.document,
            "incidentseal.workflow.json",
            now=NOW,
        )
        self.assertEqual("INVALID", result.status)
        self.assertFalse(root.exists())

    def test_forbidden_root_overlap_is_invalid(self) -> None:
        result = ApprovalStore(
            self.approval_root,
            self.repository_root,
            forbidden_roots=[self.base / "operator-state"],
        ).inspect(self.document, "incidentseal.workflow.json", now=NOW)
        self.assertEqual("INVALID", result.status)

    def test_unverified_permissions_are_invalid(self) -> None:
        self.write_approval(self.approval())
        result = ApprovalStore(
            self.approval_root,
            self.repository_root,
            permission_checker=lambda _path: False,
        ).inspect(self.document, "incidentseal.workflow.json", now=NOW)
        self.assertEqual("INVALID", result.status)
        self.assertIn("permissions", result.message)

    @unittest.skipUnless(os.name == "nt", "Windows junction probe")
    def test_junction_approval_root_is_invalid(self) -> None:
        target = self.base / "junction-target"
        target.mkdir()
        junction = self.base / "approval-junction"
        completed = subprocess.run(
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            self.skipTest("junction creation is unavailable")
        try:
            result = ApprovalStore(junction, self.repository_root).inspect(
                self.document,
                "incidentseal.workflow.json",
                now=NOW,
            )
            self.assertEqual("INVALID", result.status)
            self.assertIn("reparse", result.message)
        finally:
            os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
