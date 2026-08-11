"""Disposable real-Docker probe for approved-workflow execution internals.

This test uses an in-memory MATCH result in isolated temporary custody. It does
not write or simulate the operator-owned production approval store.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.approval import ApprovalResult  # noqa: E402
from incidentseal.manifest import load_manifest  # noqa: E402
from incidentseal.workflow import execute_workflow, read_archive_events  # noqa: E402


REMOTE = "https://github.com/example/incidentseal-disposable-workflow.git"


def run(command: list[str], cwd: Path, *, binary: bool = False) -> str | bytes:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, check=True)
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="incidentseal-real-workflow-") as temporary_value:
        temporary = Path(temporary_value)
        repository = temporary / "repository"
        repository.mkdir()
        run(["git", "init", "--quiet"], repository)
        run(["git", "config", "user.email", "incidentseal@example.invalid"], repository)
        run(["git", "config", "user.name", "IncidentSeal Probe"], repository)
        run(["git", "remote", "add", "origin", REMOTE], repository)
        (repository / ".gitignore").write_text("workflow.json\n", encoding="utf-8")
        (repository / "checks").mkdir()
        (repository / "checks" / "python_check.py").write_text(
            "import json,os\n"
            "expected=['HOME','PYTHONDONTWRITEBYTECODE','PYTHONHASHSEED','TZ']\n"
            "assert sorted(os.environ)==expected, sorted(os.environ)\n"
            "print(json.dumps({'runner':'python','environment':expected},sort_keys=True))\n",
            encoding="utf-8",
        )
        (repository / "checks" / "node_check.mjs").write_text(
            "const expected=['HOME','PYTHONDONTWRITEBYTECODE','PYTHONHASHSEED','TZ'];\n"
            "const actual=Object.keys(process.env).sort();\n"
            "if(JSON.stringify(actual)!==JSON.stringify(expected)) throw new Error(JSON.stringify(actual));\n"
            "console.log(JSON.stringify({environment:expected,runner:'node'}));\n",
            encoding="utf-8",
        )
        run(["git", "add", ".gitignore", "checks/python_check.py", "checks/node_check.mjs"], repository)
        run(["git", "commit", "--quiet", "-m", "disposable workflow"], repository)
        commit = run(["git", "rev-parse", "HEAD"], repository)
        raw_tree = run(["git", "ls-tree", "-r", "-z", "--full-tree", commit], repository, binary=True)
        tree_digest = "sha256:" + hashlib.sha256(raw_tree).hexdigest()
        manifest = {
            "schema_version": "incidentseal-workflow/v1",
            "workflow_id": "probe.real-runners",
            "revision": 1,
            "description": "Disposable exact-image Python and Node execution probe.",
            "repository": {"remote": REMOTE, "commit": commit, "tree_digest": tree_digest},
            "claim": {
                "id": "probe.passed",
                "statement": "Both disposable runner checks passed under the exact isolation profile.",
                "required_steps": ["python", "node"],
            },
            "security": {
                "container_engine_control": "host-cli-only",
                "docker_socket": "denied",
                "privileged": False,
                "host_network": False,
                "runtime_egress": "denied",
                "secrets": "denied",
                "host_mount_mode": "staged-read-only",
            },
            "steps": [
                {
                    "id": "python", "runner": "python", "command": ["python", "checks/python_check.py"], "cwd": ".",
                    "depends_on": [], "timeout_seconds": 30, "expected_exit_codes": [0], "inputs": ["checks/python_check.py"],
                    "outputs": [], "network": "none", "capture": {"stdout": "full", "stderr": "full", "max_bytes": 65536},
                },
                {
                    "id": "node", "runner": "node", "command": ["node", "checks/node_check.mjs"], "cwd": ".",
                    "depends_on": ["python"], "timeout_seconds": 30, "expected_exit_codes": [0], "inputs": ["checks/node_check.mjs"],
                    "outputs": [], "network": "none", "capture": {"stdout": "full", "stderr": "full", "max_bytes": 65536},
                },
            ],
            "evidence_policy": {
                "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
                "preserve_lifecycle": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
                "retain_attempts": "all",
            },
        }
        manifest_path = repository / "workflow.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        document = load_manifest(manifest_path)

        def temporary_approval(candidate):
            return ApprovalResult("MATCH", candidate.digest, None, None, (), None, None)

        state = temporary / "state"
        outcome = execute_workflow(
            document,
            approval_inspector=temporary_approval,
            run_root=state,
            permission_checker=lambda path: True,
        )
        raw_events, event_exit = read_archive_events(state, outcome.data["run_id"])
        candidates = run(
            ["docker", "ps", "-aq", "--filter", f"label=dev.incidentseal.workflow-run={outcome.data['run_id']}"],
            repository,
        )
        result = {
            "schema_version": "incidentseal-workflow-real-probe/v1",
            "verification_verdict": outcome.verdict,
            "lifecycle": outcome.lifecycle,
            "process_exit_code": outcome.exit_code,
            "event_stream_exit_code": event_exit,
            "event_count": len(raw_events),
            "step_ids": sorted(outcome.data["steps"]),
            "claim_permitted": outcome.data["claim_permitted"],
            "remaining_owned_containers": 0 if not candidates else len(candidates.splitlines()),
            "production_approval_written": False,
            "synthetic_temporary_authority": True,
        }
        passed = result == {
            "schema_version": "incidentseal-workflow-real-probe/v1",
            "verification_verdict": "PASS",
            "lifecycle": "completed",
            "process_exit_code": 0,
            "event_stream_exit_code": 0,
            "event_count": 10,
            "step_ids": ["node", "python"],
            "claim_permitted": True,
            "remaining_owned_containers": 0,
            "production_approval_written": False,
            "synthetic_temporary_authority": True,
        }
        result["probe_verdict"] = "PASS" if passed else "FAIL"
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
