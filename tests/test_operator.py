from __future__ import annotations

import io
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.approval import ApprovalResult, ApprovalStore, manifest_relative_path  # noqa: E402
from incidentseal.manifest import load_manifest  # noqa: E402
from incidentseal.operator import (  # noqa: E402
    ApprovalWriteError,
    approve_interactive,
    main as operator_main,
    write_approval,
)


FIXTURES = ROOT / "fixtures" / "contracts"
NOW = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC)


class TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class NonTtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return False


class CallbackTtyBuffer(TtyBuffer):
    def __init__(self, value: str, callback) -> None:
        super().__init__(value)
        self.callback = callback

    def readline(self, *args, **kwargs):
        self.callback()
        return super().readline(*args, **kwargs)


class OperatorApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="incidentseal-u04a-")
        self.base = Path(self.temporary.name)
        self.repository_root = self.base / "repository"
        self.repository_root.mkdir()
        (self.repository_root / ".git").mkdir()
        self.manifest_path = self.repository_root / "incidentseal.workflow.json"
        self.manifest_path.write_bytes((FIXTURES / "workflow.valid.minimal.json").read_bytes())
        self.approval_root = self.base / "operator-state" / "approvals" / "v1"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def approve(self, confirmation: str | None = None) -> tuple[int, str, str]:
        document = load_manifest(self.manifest_path)
        typed = document.digest if confirmation is None else confirmation
        output = TtyBuffer()
        errors = TtyBuffer()
        exit_code = approve_interactive(
            str(self.manifest_path),
            input_stream=TtyBuffer(typed + "\n"),
            output_stream=output,
            error_stream=errors,
            root=self.approval_root,
            repository_root=self.repository_root,
            approved_at=NOW,
            principal="test-operator",
        )
        return exit_code, output.getvalue(), errors.getvalue()

    def inspect(self):
        document = load_manifest(self.manifest_path)
        relative = manifest_relative_path(document, self.repository_root)
        self.assertIsNotNone(relative)
        return document, ApprovalStore(self.approval_root, self.repository_root).inspect(
            document,
            relative,
            now=NOW,
        )

    def test_exact_digest_confirmation_creates_verified_approval(self) -> None:
        exit_code, output, errors = self.approve()
        self.assertEqual(0, exit_code)
        self.assertEqual("", errors)
        self.assertIn("Canonical digest:", output)
        self.assertIn("Approved:", output)
        document, inspection = self.inspect()
        self.assertEqual("MATCH", inspection.status)
        record = json.loads(inspection.approval_path.read_text(encoding="utf-8"))
        self.assertEqual(document.digest, record["manifest_digest"])
        self.assertEqual("test-operator", record["approved_by"]["local_principal"])
        self.assertEqual([], list(inspection.approval_path.parent.glob("*.tmp")))

    def test_changed_manifest_atomically_replaces_and_retains_prior_bytes(self) -> None:
        self.assertEqual(0, self.approve()[0])
        _, first = self.inspect()
        first_path = first.approval_path
        first_bytes = first_path.read_bytes()
        value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        value["claim"]["statement"] = "A deliberately changed claim for approval supersession."
        self.manifest_path.write_text(json.dumps(value), encoding="utf-8")
        exit_code, output, errors = self.approve()
        self.assertEqual(0, exit_code)
        self.assertEqual("", errors)
        self.assertIn("Superseded record retained:", output)
        _, second = self.inspect()
        self.assertEqual("MATCH", second.status)
        self.assertNotEqual(first.approved_digest, second.approved_digest)
        superseded = list((first_path.parent / "superseded" / "example.release").glob("*.json"))
        self.assertEqual(1, len(superseded))
        self.assertEqual(first_bytes, superseded[0].read_bytes())
        self.assertEqual([], list(first_path.parent.glob("*.tmp")))

    def test_already_matching_approval_does_not_churn_history(self) -> None:
        self.assertEqual(0, self.approve()[0])
        _, first = self.inspect()
        first_bytes = first.approval_path.read_bytes()
        output = TtyBuffer()
        errors = TtyBuffer()
        exit_code = approve_interactive(
            str(self.manifest_path),
            input_stream=TtyBuffer(""),
            output_stream=output,
            error_stream=errors,
            root=self.approval_root,
            repository_root=self.repository_root,
            approved_at=NOW,
            principal="test-operator",
        )
        self.assertEqual(0, exit_code)
        self.assertIn("already matches", output.getvalue())
        self.assertEqual("", errors.getvalue())
        self.assertEqual(first_bytes, first.approval_path.read_bytes())
        self.assertFalse((first.approval_path.parent / "superseded").exists())

    def test_repository_contained_write_root_fails_without_state(self) -> None:
        document = load_manifest(self.manifest_path)
        unsafe_root = self.repository_root / ".incidentseal" / "approvals"
        with self.assertRaisesRegex(ApprovalWriteError, "overlaps repository"):
            write_approval(
                document,
                self.repository_root,
                root=unsafe_root,
                approved_at=NOW,
                principal="test-operator",
                expected_current_file_digest=None,
            )
        self.assertFalse(unsafe_root.exists())

    def test_failed_post_write_verification_restores_prior_record(self) -> None:
        self.assertEqual(0, self.approve()[0])
        _, first = self.inspect()
        first_bytes = first.approval_path.read_bytes()
        value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        value["claim"]["statement"] = "A replacement that will fail its final verification probe."
        self.manifest_path.write_text(json.dumps(value), encoding="utf-8")
        changed = load_manifest(self.manifest_path)
        invalid = ApprovalResult(
            "INVALID",
            None,
            first.approval_path,
            None,
            ("custody_or_record",),
            "IS_APPROVAL_INVALID",
            "forced final verification failure",
        )
        with patch("incidentseal.operator.ApprovalStore.inspect", return_value=invalid):
            with self.assertRaisesRegex(ApprovalWriteError, "prior state restored"):
                write_approval(
                    changed,
                    self.repository_root,
                    root=self.approval_root,
                    approved_at=NOW,
                    principal="test-operator",
                    expected_current_file_digest=first.approval_file_digest,
                )
        self.assertEqual(first_bytes, first.approval_path.read_bytes())
        self.assertEqual([], list(first.approval_path.parent.glob("*.rollback")))

    def test_manifest_change_after_prompt_fails_without_approval(self) -> None:
        document = load_manifest(self.manifest_path)

        def mutate_manifest() -> None:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            value["claim"]["statement"] = "Changed after the operator saw the digest."
            self.manifest_path.write_text(json.dumps(value), encoding="utf-8")

        errors = TtyBuffer()
        exit_code = approve_interactive(
            str(self.manifest_path),
            input_stream=CallbackTtyBuffer(document.digest + "\n", mutate_manifest),
            output_stream=TtyBuffer(),
            error_stream=errors,
            root=self.approval_root,
            repository_root=self.repository_root,
            approved_at=NOW,
            principal="test-operator",
        )
        self.assertEqual(77, exit_code)
        self.assertIn("manifest changed after review", errors.getvalue())
        self.assertFalse(self.approval_root.exists())

    def test_approval_change_after_prompt_fails_without_replacement(self) -> None:
        document = load_manifest(self.manifest_path)
        remote_key = hashlib.sha256(document.value["repository"]["remote"].encode("utf-8")).hexdigest()
        approval_path = self.approval_root / remote_key / "example.release.json"

        def create_competing_approval() -> None:
            approval_path.parent.mkdir(parents=True, exist_ok=True)
            value = json.loads((FIXTURES / "approval.valid.json").read_text(encoding="utf-8"))
            value["manifest_path"] = "incidentseal.workflow.json"
            approval_path.write_text(json.dumps(value), encoding="utf-8")

        errors = TtyBuffer()
        exit_code = approve_interactive(
            str(self.manifest_path),
            input_stream=CallbackTtyBuffer(document.digest + "\n", create_competing_approval),
            output_stream=TtyBuffer(),
            error_stream=errors,
            root=self.approval_root,
            repository_root=self.repository_root,
            approved_at=NOW,
            principal="test-operator",
        )
        self.assertEqual(77, exit_code)
        self.assertIn("approval state changed after review", errors.getvalue())
        self.assertEqual(document.digest, json.loads(approval_path.read_text(encoding="utf-8"))["manifest_digest"])

    def test_wrong_digest_cancels_without_creating_store(self) -> None:
        exit_code, _output, errors = self.approve("sha256:" + "0" * 64)
        self.assertEqual(20, exit_code)
        self.assertIn("cancelled", errors)
        self.assertFalse(self.approval_root.exists())

    def test_redirected_input_is_forbidden_without_writing(self) -> None:
        errors = io.StringIO()
        exit_code = approve_interactive(
            str(self.manifest_path),
            input_stream=NonTtyBuffer(""),
            output_stream=TtyBuffer(),
            error_stream=errors,
            root=self.approval_root,
            repository_root=self.repository_root,
        )
        self.assertEqual(77, exit_code)
        self.assertIn("interactive terminal", errors.getvalue())
        self.assertFalse(self.approval_root.exists())

    def test_operator_parser_has_no_noninteractive_confirmation_flag(self) -> None:
        errors = io.StringIO()
        exit_code = operator_main(
            ["--manifest", str(self.manifest_path), "--yes"],
            input_stream=TtyBuffer(),
            output_stream=TtyBuffer(),
            error_stream=errors,
        )
        self.assertEqual(64, exit_code)
        self.assertIn("Usage:", errors.getvalue())
        self.assertFalse(self.approval_root.exists())


if __name__ == "__main__":
    unittest.main()
