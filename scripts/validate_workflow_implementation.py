#!/usr/bin/env python3
"""Validate the locked approved-workflow implementation without starting runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


EXPECTED_PATHS = (
    "AGENTS.md",
    "docs/cli-contract.md",
    "docs/decisions/ADR-0013-no-shell-distroless-command-bootstrap.md",
    "docs/workflow-verification-contract.md",
    "docs/workflow-verification-implementation.md",
    "fixtures/workflow-verification/implementation-mutations.json",
    "requirements/topology-runtime.lock.json",
    "requirements/workflow-verification-contract.lock.json",
    "scripts/materialize_release_workflow.py",
    "scripts/probe_workflow_execution.py",
    "scripts/probe_workflow_recovery.py",
    "scripts/test_workflow_implementation_mutations.py",
    "scripts/validate_workflow_implementation.py",
    "scripts/verify_workflow_release_gate.mjs",
    "src/incidentseal/approval.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/journal.py",
    "src/incidentseal/manifest.py",
    "src/incidentseal/workflow.py",
    "tests/test_cli.py",
    "tests/test_release_workflow.py",
    "tests/test_workflow.py",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def container_ids(docker: str | None, root: Path) -> tuple[str, ...]:
    if docker is None:
        return ()
    completed = subprocess.run(
        [docker, "ps", "-aq"], cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
    )
    require(completed.returncode == 0, "Docker history could not be observed")
    return tuple(completed.stdout.splitlines())


def validate(root: Path, *, static_only: bool = False) -> dict[str, Any]:
    root = root.resolve(strict=True)
    lock_path = root / "requirements" / "workflow-verification-implementation.lock.json"
    lock = load(lock_path)
    require(lock.get("schema_version") == "incidentseal-workflow-verification-implementation-lock/v1", "implementation lock version differs")
    entries = lock.get("files")
    require(isinstance(entries, list), "implementation lock files are absent")
    require(tuple(item.get("path") for item in entries if isinstance(item, dict)) == EXPECTED_PATHS, "implementation lock scope differs")
    require(len(entries) == len(set(EXPECTED_PATHS)), "implementation lock paths are duplicated")
    for entry in entries:
        path = root / entry["path"]
        require(path.is_file() and digest(path) == entry.get("sha256"), f"implementation drift: {entry.get('path')}")
    require(
        lock.get("workflow_contract_lock") == {
            "path": "requirements/workflow-verification-contract.lock.json",
            "sha256": digest(root / "requirements" / "workflow-verification-contract.lock.json"),
        },
        "workflow contract binding differs",
    )
    require(
        lock.get("topology_runtime_lock") == {
            "path": "requirements/topology-runtime.lock.json",
            "sha256": digest(root / "requirements" / "topology-runtime.lock.json"),
        },
        "topology runtime binding differs",
    )
    require(lock.get("supported_runners") == ["python", "node"], "supported runner set differs")
    require(lock.get("runtime_dependencies") == [], "workflow implementation added runtime dependencies")
    require(lock.get("agent_commands") == ["verify", "run.events"], "agent command set differs")
    require(lock.get("approval_mutation_command") is False, "agent approval mutation became available")

    source = (root / "src" / "incidentseal" / "workflow.py").read_text(encoding="utf-8")
    cli = (root / "src" / "incidentseal" / "cli.py").read_text(encoding="utf-8")
    guidance = (root / "docs" / "workflow-verification-implementation.md").read_text(encoding="utf-8")
    materializer = (root / "scripts" / "materialize_release_workflow.py").read_text(encoding="utf-8")
    node_gate = (root / "scripts" / "verify_workflow_release_gate.mjs").read_text(encoding="utf-8")
    for fragment in (
        "approval, snapshot = preflight_workflow(document, approval_inspector=approval_inspector)",
        "approval = require_approval(document, approval_inspector)",
        'if step["runner"] not in ENTRYPOINTS',
        'if step["outputs"]',
        'remote != document.value["repository"]["remote"]',
        'commit != document.value["repository"]["commit"]',
        'if status:',
        'tree_digest != document.value["repository"]["tree_digest"]',
        "_is_onedrive(root)",
        "_has_reparse_or_symlink(current)",
        '"--network", "none"',
        '"--user", "65532:65532"',
        '"--read-only", "--cap-drop", "ALL"',
        '"--security-opt", "no-new-privileges"',
        '"--pids-limit", "64"',
        '"--memory", "536870912"',
        "os.environ.clear();os.environ.update(e)",
        "shell:false",
        'self.events_path.open("ab", buffering=0)',
        'stream.write(raw + b"\\n")\n            os.fsync(stream.fileno())',
        'labels.get(key) == expected',
        'f"label=dev.incidentseal.workflow-run={run_id}"',
        'archive.append("run.cancelled", "cancelled"',
        '"run.stale",\n                "stale",',
        'active_key": "repository-remote+workflow-id+manifest-digest+commit+tree-digest"' if 'active_key": "repository-remote+workflow-id+manifest-digest+commit+tree-digest"' in source else '"schema_version": "incidentseal-workflow-active-key/v1"',
    ):
        require(fragment in source, f"required workflow boundary is absent: {fragment}")
    for forbidden in ("shell=True", "os.system(", '"--privileged"', '"--network", "host"', "/var/run/docker.sock"):
        require(forbidden not in source, f"forbidden workflow boundary is present: {forbidden}")
    require(source.count("labels.get(key) == expected") == 2, "runtime and recovery label checks differ")
    execution = source[source.index("def execute_workflow(") : source.index("def read_archive_events(")]
    require(execution.index("preflight_workflow") < execution.index("docker_executable()"), "Docker access precedes authority and repository preflight")
    require(execution.index("_stage(snapshot, stage)") < execution.index("_state_root("), "evidence custody is created before exact staging")
    require(execution.count("require_approval(document, approval_inspector)") >= 2, "approval is not rechecked after staging and before steps")
    require('command = "verify" if is_verify' in cli and 'request.command == "verify"' in cli, "verify CLI dispatch is absent")
    require("stream_workflow_events" in cli and 'tuple(arguments[:2]) == ("run", "events")' in cli, "workflow event read dispatch is absent")
    require('("run", "append")' not in cli and 'command = "operator.approve-manifest"' not in cli, "agent write surface is exposed")
    require("temporary in-process test authority" in guidance, "synthetic authority limit is undocumented")
    for fragment in (
        'OUTPUT = ROOT / ".incidentseal" / "workflow.json"',
        'status = run_git(["status", "--porcelain"])\n    if status:\n        raise RuntimeError("release workflow materialization requires a clean worktree")',
        '"check-ignore", "-q", "--", ".incidentseal/workflow.json"',
        '"approval_written": False',
    ):
        require(fragment in materializer, f"release workflow materializer boundary is absent: {fragment}")
    require("operator approve-manifest" not in materializer and "write_approval" not in materializer, "materializer gained approval authority")
    for fragment in (
        "must(actual === entry.sha256, `implementation drift: ${entry.path}`);",
        'must(authority.agent_can_approve === false, "agent approval boundary differs");',
        'must(runtime.runtime_network === "none", "runtime network differs");',
        'must(runtime.docker_socket === "denied" && runtime.secrets === "denied", "socket or secret boundary differs");',
        'must(u03?.status === "planned", "packaging advanced before workflow verification");',
    ):
        require(fragment in node_gate, f"Node release gate boundary is absent: {fragment}")

    docker = shutil.which("docker")
    before = container_ids(docker, root)
    tests = 0
    if not static_only:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(root / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "tests.test_workflow", "tests.test_cli", "tests.test_release_workflow"],
            cwd=root, env=environment, capture_output=True, text=True, encoding="utf-8", timeout=120, check=False,
        )
        require(completed.returncode == 0, f"workflow unit tests failed: {completed.stdout}{completed.stderr}")
        tests = 23
    after = container_ids(docker, root)
    require(before == after, "static workflow validation changed Docker container history")
    return {
        "schema_version": "incidentseal-workflow-verification-implementation-validation/v1",
        "verification_verdict": "PASS",
        "implementation_lock_digest": digest(lock_path),
        "unit_tests": tests,
        "supported_runners": 2,
        "runtime_dependencies": 0,
        "approval_mutation_command": False,
        "runtime_started": False,
        "container_history_unchanged": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--static-only", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, static_only=args.static_only), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-workflow-verification-implementation-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_WORKFLOW_IMPLEMENTATION", "message": str(error)},
            "runtime_started": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
