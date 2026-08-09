from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FIXTURES = ROOT / "fixtures" / "contracts"
sys.path.insert(0, str(ROOT))

from scripts.validate_machine_contracts import (  # noqa: E402
    load_schema_documents,
    validate_schema_instance,
)


EXPECTED = "sha256:0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45"
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = load_schema_documents()

    def run_cli(self, *arguments: str) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SRC) + os.pathsep + environment.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, "-m", "incidentseal", *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertTrue(completed.stdout.endswith(b"\n"))
        self.assertEqual(1, completed.stdout.count(b"\n"))
        self.assertEqual(b"", completed.stderr)
        envelope = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(completed.returncode, envelope["process_exit_code"])
        self.assertRegex(envelope["invocation_id"], UUID4_RE)
        validate_schema_instance(
            self.schemas["cli-envelope-v1.schema.json"],
            envelope,
            "cli-envelope-v1.schema.json",
            self.schemas,
        )
        return completed, envelope

    def test_policy_lint_success(self) -> None:
        completed, envelope = self.run_cli(
            "policy", "lint", "--manifest", str(FIXTURES / "workflow.valid.minimal.json"), "--json"
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual("policy.lint", envelope["command"])
        self.assertEqual("succeeded", envelope["command_status"])
        self.assertTrue(envelope["data"]["valid"])
        self.assertIsNone(envelope["verdict"])

    def test_policy_digest_is_format_invariant(self) -> None:
        digests = []
        for name in ("workflow.valid.minimal.json", "workflow.valid.reordered.json"):
            completed, envelope = self.run_cli(
                "policy", "digest", "--json", "--manifest", str(FIXTURES / name)
            )
            self.assertEqual(0, completed.returncode)
            self.assertEqual("RFC8785-JCS", envelope["data"]["algorithm"])
            digests.append(envelope["data"]["manifest_digest"])
        self.assertEqual([EXPECTED, EXPECTED], digests)

    def test_invalid_manifests_fail_closed(self) -> None:
        cases = {
            "workflow.invalid.duplicate-key.json": "IS_MANIFEST_DUPLICATE_KEY",
            "workflow.invalid.float.json": "IS_MANIFEST_NUMBER_DOMAIN",
            "workflow.invalid.network.json": "IS_MANIFEST_SCHEMA",
        }
        for name, expected_code in cases.items():
            with self.subTest(name=name):
                completed, envelope = self.run_cli(
                    "policy", "lint", "--manifest", str(FIXTURES / name), "--json"
                )
                self.assertEqual(12, completed.returncode)
                self.assertEqual("rejected", envelope["command_status"])
                self.assertEqual("INVALID", envelope["verdict"])
                self.assertEqual(expected_code, envelope["errors"][0]["code"])

    def test_usage_and_missing_input_have_stable_exits(self) -> None:
        completed, envelope = self.run_cli("policy", "lint", "--json")
        self.assertEqual(64, completed.returncode)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])
        completed, envelope = self.run_cli(
            "policy", "lint", "--manifest", str(ROOT / "does-not-exist.json"), "--json"
        )
        self.assertEqual(74, completed.returncode)
        self.assertEqual("IS_MANIFEST_READ", envelope["errors"][0]["code"])

    def test_default_approval_status_is_missing_and_read_only(self) -> None:
        approval_root = Path(os.environ["LOCALAPPDATA"]) / "IncidentSeal" / "approvals" / "v1"
        self.assertFalse(approval_root.exists(), "test requires no real IncidentSeal approval store")
        for command in ("status", "diff"):
            with self.subTest(command=command):
                completed, envelope = self.run_cli(
                    "policy", command, "--manifest", str(FIXTURES / "workflow.valid.minimal.json"), "--json"
                )
                self.assertEqual(12, completed.returncode)
                self.assertEqual("MISSING", envelope["policy"]["approval_status"])
                self.assertEqual("INVALID", envelope["verdict"])
                self.assertEqual("IS_APPROVAL_MISSING", envelope["errors"][0]["code"])
        self.assertFalse(approval_root.exists())

    def test_agent_facing_approval_attempt_is_forbidden(self) -> None:
        completed, envelope = self.run_cli(
            "operator",
            "approve-manifest",
            "--manifest",
            str(FIXTURES / "workflow.valid.minimal.json"),
            "--json",
        )
        self.assertEqual(77, completed.returncode)
        self.assertEqual("operator.approve-manifest", envelope["command"])
        self.assertEqual("IS_AUTHORITY_MUTATION_FORBIDDEN", envelope["errors"][0]["code"])

    def test_agent_cannot_select_an_approval_root(self) -> None:
        completed, envelope = self.run_cli(
            "policy",
            "status",
            "--manifest",
            str(FIXTURES / "workflow.valid.minimal.json"),
            "--approval-root",
            str(ROOT / "fixtures"),
            "--json",
        )
        self.assertEqual(64, completed.returncode)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])

    @unittest.skipUnless(os.name == "nt", "Windows launcher probe")
    def test_windows_launcher_runs_real_cli(self) -> None:
        completed = subprocess.run(
            [
                os.environ.get("COMSPEC", "cmd.exe"),
                "/d",
                "/c",
                str(ROOT / "incidentseal.cmd"),
                "policy",
                "digest",
                "--manifest",
                str(FIXTURES / "workflow.valid.minimal.json"),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr.decode(errors="replace"))
        envelope = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(EXPECTED, envelope["data"]["manifest_digest"])


if __name__ == "__main__":
    unittest.main()
