from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from incidentseal.cli import execute  # noqa: E402


class TopologyTests(unittest.TestCase):
    def test_non_platform_mode_is_rejected_before_docker(self) -> None:
        envelope, exit_code = execute(["topology", "validate", "--mode", "workflow-execution", "--json"])
        self.assertEqual(64, exit_code)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])

    def test_topology_command_rejects_manifest_argument(self) -> None:
        envelope, exit_code = execute(
            ["topology", "validate", "--mode", "platform-validation", "--manifest", "ignored.json", "--json"]
        )
        self.assertEqual(64, exit_code)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])

    @unittest.skipUnless(shutil.which("node"), "Node.js source self-test")
    def test_runner_self_tests_share_the_input_digest(self) -> None:
        commands = (
            [sys.executable, "-B", str(ROOT / "containers" / "python-runner" / "python_runner.py"), "--self-test"],
            ["node", str(ROOT / "containers" / "node-runner" / "node_runner.mjs"), "--self-test"],
        )
        results = []
        for command in commands:
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("", completed.stderr)
            results.append(json.loads(completed.stdout))
        self.assertEqual(results[0]["input_digest"], results[1]["input_digest"])
        self.assertEqual({"python", "node"}, {result["runner"] for result in results})
        self.assertTrue(all(result["database_verified"] is False for result in results))


if __name__ == "__main__":
    unittest.main()
