from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from incidentseal.approval import ApprovalResult
from incidentseal.manifest import load_manifest
from incidentseal.workflow import (
    RunArchive,
    WorkflowError,
    _capture,
    _stage,
    execute_workflow,
    inspect_repository,
    preflight_workflow,
    read_archive_events,
)


REMOTE = "https://github.com/example/incidentseal-workflow-fixture.git"


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="incidentseal-workflow-test-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.email", "incidentseal@example.invalid")
        self.git("config", "user.name", "IncidentSeal Test")
        self.git("remote", "add", "origin", REMOTE)
        (self.repo / ".gitignore").write_text("workflow.json\n", encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "check.py").write_text("print('ok')\n", encoding="utf-8")
        self.git("add", ".gitignore", "src/check.py")
        self.git("commit", "--quiet", "-m", "fixture")
        self.refresh_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str, binary: bool = False) -> str | bytes:
        result = subprocess.run(["git", "-C", str(self.repo), *arguments], capture_output=True, check=True)
        return result.stdout if binary else result.stdout.decode("utf-8").strip()

    def refresh_manifest(self, *, runner: str = "python", command: list[str] | None = None, inputs: list[str] | None = None) -> None:
        commit = self.git("rev-parse", "HEAD")
        raw_tree = self.git("ls-tree", "-r", "-z", "--full-tree", commit, binary=True)
        tree_digest = "sha256:" + hashlib.sha256(raw_tree).hexdigest()
        value = {
            "schema_version": "incidentseal-workflow/v1",
            "workflow_id": "fixture.verify",
            "revision": 1,
            "repository": {"remote": REMOTE, "commit": commit, "tree_digest": tree_digest},
            "claim": {"id": "fixture.passed", "statement": "Fixture passed.", "required_steps": ["unit"]},
            "security": {
                "container_engine_control": "host-cli-only", "docker_socket": "denied", "privileged": False,
                "host_network": False, "runtime_egress": "denied", "secrets": "denied", "host_mount_mode": "staged-read-only",
            },
            "steps": [{
                "id": "unit", "runner": runner, "command": command or [runner, "src/check.py"], "cwd": ".",
                "depends_on": [], "timeout_seconds": 30, "expected_exit_codes": [0], "inputs": inputs or ["src"],
                "outputs": [], "network": "none", "capture": {"stdout": "full", "stderr": "full", "max_bytes": 4096},
            }],
            "evidence_policy": {
                "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
                "preserve_lifecycle": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
                "retain_attempts": "all",
            },
        }
        (self.repo / "workflow.json").write_text(json.dumps(value), encoding="utf-8")
        self.document = load_manifest(self.repo / "workflow.json")

    def approval(self, document) -> ApprovalResult:
        return ApprovalResult("MATCH", document.digest, None, None, (), None, None)

    def test_exact_clean_repository_preflight_selects_only_declared_inputs(self) -> None:
        approval, snapshot = preflight_workflow(self.document, approval_inspector=self.approval)
        self.assertTrue(approval.approved)
        self.assertEqual(("src/check.py",), snapshot.selected)
        object_id = self.git("rev-parse", "HEAD:src/check.py")
        self.assertEqual(len(self.git("cat-file", "blob", object_id, binary=True)), snapshot.total_bytes)

    def test_missing_approval_precedes_repository_and_docker_policy(self) -> None:
        missing = lambda document: ApprovalResult("MISSING", None, None, None, ("approval",), "IS_APPROVAL_MISSING", "approval is missing")
        value = json.loads((self.repo / "workflow.json").read_text(encoding="utf-8"))
        value["repository"]["commit"] = "0" * 40
        (self.repo / "workflow.json").write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(WorkflowError, "approval is missing") as caught:
            preflight_workflow(load_manifest(self.repo / "workflow.json"), approval_inspector=missing)
        self.assertEqual("IS_APPROVAL_MISSING", caught.exception.code)

    def test_unsupported_schema_valid_runner_fails_before_runtime(self) -> None:
        self.refresh_manifest(runner="host", command=["host", "echo"])
        with self.assertRaises(WorkflowError) as caught:
            preflight_workflow(self.document, approval_inspector=self.approval)
        self.assertEqual("IS_WORKFLOW_RUNNER", caught.exception.code)

    def test_dirty_worktree_and_wrong_tree_digest_fail_closed(self) -> None:
        (self.repo / "dirty.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaises(WorkflowError) as caught:
            inspect_repository(self.document)
        self.assertEqual("IS_WORKFLOW_DIRTY", caught.exception.code)
        (self.repo / "dirty.txt").unlink()
        value = json.loads((self.repo / "workflow.json").read_text(encoding="utf-8"))
        value["repository"]["tree_digest"] = "sha256:" + "0" * 64
        (self.repo / "workflow.json").write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(WorkflowError) as caught:
            inspect_repository(load_manifest(self.repo / "workflow.json"))
        self.assertEqual("IS_WORKFLOW_TREE_DIGEST", caught.exception.code)

    def test_overlapping_inputs_and_persistent_outputs_fail_closed(self) -> None:
        self.refresh_manifest(inputs=["src", "src/check.py"])
        with self.assertRaises(WorkflowError) as caught:
            inspect_repository(self.document)
        self.assertEqual("IS_WORKFLOW_INPUT_OVERLAP", caught.exception.code)
        value = json.loads((self.repo / "workflow.json").read_text(encoding="utf-8"))
        value["steps"][0]["inputs"] = ["src"]
        value["steps"][0]["outputs"] = ["result.json"]
        (self.repo / "workflow.json").write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(WorkflowError) as caught:
            inspect_repository(load_manifest(self.repo / "workflow.json"))
        self.assertEqual("IS_WORKFLOW_OUTPUTS", caught.exception.code)

    def test_staging_uses_committed_bytes_not_mutable_worktree_bytes(self) -> None:
        snapshot = inspect_repository(self.document)
        stage = self.root / "stage" / "workspace"
        _stage(snapshot, stage)
        self.assertEqual(b"print('ok')\n", (stage / "src" / "check.py").read_bytes())
        self.assertFalse(os.access(stage / "src" / "check.py", os.W_OK) and os.name != "nt")

    def test_capture_modes_and_limit_preserve_independent_truth(self) -> None:
        raw = b"ok\x00bytes"
        full = _capture(raw, "full", len(raw))
        self.assertEqual("base64", full["encoding"])
        self.assertIsNotNone(full["content"])
        self.assertIsNone(_capture(raw, "hash", len(raw))["content"])
        self.assertIsNone(_capture(raw, "none", len(raw))["digest"])
        with self.assertRaises(WorkflowError) as caught:
            _capture(raw, "full", len(raw) - 1)
        self.assertEqual("INCONCLUSIVE", caught.exception.verdict)

    def test_external_event_archive_is_canonical_append_only_and_terminal(self) -> None:
        state = self.root / "state"
        state.mkdir()
        (state / "runs").mkdir()
        run_id = str(uuid.uuid4())
        approval = self.approval(self.document)
        archive = RunArchive(state, run_id, self.document, approval)
        archive.create()
        archive.append("run.queued", "queued")
        archive.append("run.started", "running")
        archive.append("run.completed", "completed", verdict="PASS")
        raw, exit_code = read_archive_events(state, run_id)
        self.assertEqual(3, len(raw))
        self.assertEqual(0, exit_code)
        with archive.events_path.open("ab") as stream:
            stream.write(raw[-1] + b"\n")
        with self.assertRaises(WorkflowError):
            read_archive_events(state, run_id)

    def test_runtime_unavailable_retains_failed_lifecycle_and_run_id(self) -> None:
        state = self.root / "failed-state"

        def unavailable():
            raise OSError("Docker unavailable")

        with self.assertRaises(WorkflowError) as caught:
            execute_workflow(
                self.document,
                approval_inspector=self.approval,
                run_root=state,
                permission_checker=lambda path: True,
                docker_executable=unavailable,
            )
        error = caught.exception
        self.assertEqual(21, error.exit_code)
        self.assertEqual("failed", error.lifecycle)
        self.assertIsNone(error.verdict)
        self.assertIn("run_id", error.data)
        raw, exit_code = read_archive_events(state, error.data["run_id"])
        self.assertEqual(3, len(raw))
        self.assertEqual(21, exit_code)


if __name__ == "__main__":
    unittest.main()
