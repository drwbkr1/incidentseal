from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import canonical_bytes  # noqa: E402
from materialize_release_workflow import INPUTS, OUTPUT, REMOTE, WORKFLOW_ID, build_manifest  # noqa: E402


class ReleaseWorkflowTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_closed(self) -> None:
        commit = "1" * 40
        tree = "sha256:" + "2" * 64
        first = build_manifest(commit, tree)
        second = build_manifest(commit, tree)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["workflow_id"], WORKFLOW_ID)
        self.assertEqual(first["repository"], {"remote": REMOTE, "commit": commit, "tree_digest": tree})
        self.assertEqual(first["claim"]["required_steps"], ["python-implementation-lock", "node-release-gate"])
        self.assertEqual(first["steps"][0]["inputs"], INPUTS)
        self.assertEqual(first["steps"][1]["depends_on"], ["python-implementation-lock"])
        self.assertTrue(all(step["network"] == "none" and step["outputs"] == [] for step in first["steps"]))

    def test_materializer_has_fixed_ignored_custody_and_no_approval_command(self) -> None:
        source = (ROOT / "scripts" / "materialize_release_workflow.py").read_text(encoding="utf-8")
        self.assertEqual(OUTPUT, ROOT / ".incidentseal" / "workflow.json")
        self.assertIn('run_git(["status", "--porcelain"])', source)
        self.assertIn('"check-ignore", "-q", "--", ".incidentseal/workflow.json"', source)
        self.assertNotIn("operator approve-manifest", source)
        self.assertNotIn("write_approval", source)

    def test_node_gate_verifies_current_locked_candidate(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        completed = subprocess.run(
            [str(node), "scripts/verify_workflow_release_gate.mjs"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        value = json.loads(completed.stdout)
        self.assertEqual(value["verification_verdict"], "PASS")
        self.assertFalse(value["approval_mutation_command"])


if __name__ == "__main__":
    unittest.main()
