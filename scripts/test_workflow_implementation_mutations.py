#!/usr/bin/env python3
"""Require every unsafe approved-workflow implementation mutation to fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    old: str
    new: str
    refresh_lock: bool = True


MUTATIONS = (
    Mutation("approval-preflight-removed", "src/incidentseal/workflow.py", "approval, snapshot = preflight_workflow(document, approval_inspector=approval_inspector)", "approval = require_approval(document, approval_inspector); snapshot = inspect_repository(document)"),
    Mutation("approval-step-recheck-removed", "src/incidentseal/workflow.py", "approval = require_approval(document, approval_inspector)\n                archive.append", "approval = approval\n                archive.append"),
    Mutation("unsupported-runner-allowed", "src/incidentseal/workflow.py", 'if step["runner"] not in ENTRYPOINTS:', "if False:"),
    Mutation("persistent-output-allowed", "src/incidentseal/workflow.py", 'if step["outputs"]:', "if False:"),
    Mutation("origin-check-removed", "src/incidentseal/workflow.py", 'if remote != document.value["repository"]["remote"]:', "if False:"),
    Mutation("head-check-removed", "src/incidentseal/workflow.py", 'if commit != document.value["repository"]["commit"]:', "if False:"),
    Mutation("clean-check-removed", "src/incidentseal/workflow.py", "if status:\n        raise WorkflowError", "if False:\n        raise WorkflowError"),
    Mutation("tree-digest-check-removed", "src/incidentseal/workflow.py", 'if tree_digest != document.value["repository"]["tree_digest"]:', "if False:"),
    Mutation("onedrive-check-removed", "src/incidentseal/workflow.py", "if _is_onedrive(root):", "if False:"),
    Mutation("reparse-check-removed", "src/incidentseal/workflow.py", "if _has_reparse_or_symlink(current):", "if False:"),
    Mutation("network-isolation-removed", "src/incidentseal/workflow.py", '"--network", "none"', '"--network", "bridge"'),
    Mutation("read-only-root-removed", "src/incidentseal/workflow.py", '"--read-only", "--cap-drop", "ALL"', '"--cap-drop", "ALL"'),
    Mutation("capability-drop-removed", "src/incidentseal/workflow.py", '"--read-only", "--cap-drop", "ALL"', '"--read-only"'),
    Mutation("no-new-privileges-removed", "src/incidentseal/workflow.py", '"--security-opt", "no-new-privileges"', '"--security-opt", "seccomp=unconfined"'),
    Mutation("pids-limit-removed", "src/incidentseal/workflow.py", '"--pids-limit", "64"', '"--pids-limit", "0"'),
    Mutation("memory-limit-removed", "src/incidentseal/workflow.py", '"--memory", "536870912"', '"--memory", "0"'),
    Mutation("environment-clear-removed", "src/incidentseal/workflow.py", "os.environ.clear();os.environ.update(e)", "os.environ.update(e)"),
    Mutation("node-shell-enabled", "src/incidentseal/workflow.py", "shell:false", "shell:true"),
    Mutation("append-mode-replaced", "src/incidentseal/workflow.py", 'self.events_path.open("ab", buffering=0)', 'self.events_path.open("wb", buffering=0)'),
    Mutation("event-fsync-removed", "src/incidentseal/workflow.py", 'stream.write(raw + b"\\n")\n            os.fsync(stream.fileno())', 'stream.write(raw + b"\\n")\n            stream.flush()'),
    Mutation("runtime-label-check-removed", "src/incidentseal/workflow.py", "labels.get(key) == expected", "True"),
    Mutation("owned-filter-removed", "src/incidentseal/workflow.py", 'f"label=dev.incidentseal.workflow-run={run_id}"', '"label=dev.incidentseal.workflow-run"'),
    Mutation("agent-approval-exposed", "src/incidentseal/cli.py", "COMMANDS = {", 'COMMANDS = {\n    ("run", "append"): "run.append",'),
    Mutation("implementation-lock-tampered", "requirements/workflow-verification-implementation.lock.json", '"sha256":"sha256:', '"sha256":"sha256:0', refresh_lock=False),
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_lock(root: Path, changed_path: str) -> None:
    path = root / "requirements" / "workflow-verification-implementation.lock.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    matched = False
    for entry in value["files"]:
        if entry["path"] == changed_path:
            entry["sha256"] = digest(root / changed_path)
            matched = True
    if not matched:
        raise RuntimeError(f"mutation path is not locked: {changed_path}")
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    manifest = json.loads((ROOT / "fixtures" / "workflow-verification" / "implementation-mutations.json").read_text(encoding="utf-8"))
    if [item["id"] for item in manifest["mutations"]] != [item.id for item in MUTATIONS]:
        raise RuntimeError("workflow implementation mutation manifest differs")
    results = []
    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="incidentseal-workflow-implementation-mutation-") as temporary:
            candidate = Path(temporary) / "repo"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            path = candidate / mutation.path
            source = path.read_text(encoding="utf-8")
            if mutation.old not in source:
                raise RuntimeError(f"mutation anchor is absent: {mutation.id}")
            path.write_text(source.replace(mutation.old, mutation.new, 1), encoding="utf-8")
            if mutation.refresh_lock:
                refresh_lock(candidate, mutation.path)
            completed = subprocess.run(
                [sys.executable, "-B", str(candidate / "scripts" / "validate_workflow_implementation.py"), "--root", str(candidate), "--static-only"],
                cwd=candidate, capture_output=True, text=True, encoding="utf-8", timeout=60, check=False,
            )
            try:
                value = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"mutation validator output is invalid: {mutation.id}") from error
            passed = completed.returncode == 1 and value.get("verification_verdict") == "INVALID" and not completed.stderr
            results.append({"id": mutation.id, "verification_verdict": "PASS" if passed else "FAIL"})
            if not passed:
                raise RuntimeError(f"unsafe mutation was not rejected: {mutation.id}: {completed.stdout}{completed.stderr}")
    print(json.dumps({
        "schema_version": "incidentseal-workflow-verification-implementation-mutation-results/v1",
        "verification_verdict": "PASS",
        "mutation_count": len(results),
        "mutations": results,
        "runtime_started": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
