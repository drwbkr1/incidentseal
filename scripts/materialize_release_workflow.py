#!/usr/bin/env python3
"""Materialize one deterministic ignored IncidentSeal release workflow manifest.

This utility never reads or writes operator approval. A changed manifest still
requires a new external exact-digest approval before ``incidentseal verify`` can
reach Git inspection or Docker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import canonical_bytes, validate_manifest  # noqa: E402


OUTPUT = ROOT / ".incidentseal" / "workflow.json"
SUPERSEDED = ROOT / ".incidentseal" / "superseded"
REMOTE = "https://github.com/drwbkr1/incidentseal.git"
WORKFLOW_ID = "incidentseal.v0.1.0.prepackage"
INPUTS = ["AGENTS.md", "contracts", "docs", "fixtures", "requirements", "scripts", "src", "tests"]


def run_git(arguments: list[str], *, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git command failed: {' '.join(arguments)}: {detail}")
    if binary:
        return completed.stdout
    return completed.stdout.decode("utf-8").strip()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def is_reparse(path: Path) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(value, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def inspect_repository() -> tuple[str, str]:
    if any(part.casefold() == "onedrive" for part in ROOT.parts):
        raise RuntimeError("IncidentSeal release workflow custody may not be in OneDrive")
    if Path(run_git(["rev-parse", "--show-toplevel"])).resolve() != ROOT:
        raise RuntimeError("canonical repository root differs")
    if run_git(["branch", "--show-current"]) != "main":
        raise RuntimeError("release workflow materialization requires main")
    if run_git(["remote", "get-url", "origin"]) != REMOTE:
        raise RuntimeError("origin remote differs")
    status = run_git(["status", "--porcelain"])
    if status:
        raise RuntimeError("release workflow materialization requires a clean worktree")
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", ".incidentseal/workflow.json"],
        cwd=ROOT, capture_output=True, check=False,
    )
    if ignored.returncode != 0:
        raise RuntimeError("fixed release workflow path is not ignored")
    if is_reparse(ROOT) or is_reparse(OUTPUT.parent) or is_reparse(OUTPUT):
        raise RuntimeError("release workflow custody may not cross a symlink or reparse point")
    commit = str(run_git(["rev-parse", "HEAD"]))
    tree = digest(bytes(run_git(["ls-tree", "-r", "-z", "--full-tree", commit], binary=True)))
    return commit, tree


def build_manifest(commit: str, tree_digest: str) -> dict[str, Any]:
    manifest = {
        "schema_version": "incidentseal-workflow/v1",
        "workflow_id": WORKFLOW_ID,
        "revision": 1,
        "description": "Pre-package verification of the public bounded IncidentSeal workflow implementation in exact pinned Python and Node images.",
        "repository": {"remote": REMOTE, "commit": commit, "tree_digest": tree_digest},
        "claim": {
            "id": "incidentseal.prepackage.verifier-ready",
            "statement": "The public IncidentSeal verifier implementation and release-bound trust checks passed in pinned Python and Node containers under this exact operator-approved manifest.",
            "required_steps": ["python-implementation-lock", "node-release-gate"],
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
                "id": "python-implementation-lock",
                "runner": "python",
                "command": ["python", "scripts/validate_workflow_implementation.py", "--static-only"],
                "cwd": ".",
                "depends_on": [],
                "timeout_seconds": 120,
                "expected_exit_codes": [0],
                "inputs": INPUTS,
                "outputs": [],
                "network": "none",
                "capture": {"stdout": "full", "stderr": "full", "max_bytes": 1048576},
            },
            {
                "id": "node-release-gate",
                "runner": "node",
                "command": ["node", "scripts/verify_workflow_release_gate.mjs"],
                "cwd": ".",
                "depends_on": ["python-implementation-lock"],
                "timeout_seconds": 120,
                "expected_exit_codes": [0],
                "inputs": INPUTS,
                "outputs": [],
                "network": "none",
                "capture": {"stdout": "full", "stderr": "full", "max_bytes": 1048576},
            },
        ],
        "evidence_policy": {
            "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
            "preserve_lifecycle": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
            "retain_attempts": "all",
        },
    }
    return validate_manifest(manifest)


def atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.parent / f".workflow.{uuid.uuid4()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def materialize(*, check_only: bool, replace: bool) -> dict[str, Any]:
    commit, tree_digest = inspect_repository()
    payload = canonical_bytes(build_manifest(commit, tree_digest))
    manifest_digest = digest(payload)
    state = "checked"
    if not check_only:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        if is_reparse(OUTPUT.parent):
            raise RuntimeError("release workflow custody became a reparse point")
        if OUTPUT.exists():
            existing = OUTPUT.read_bytes()
            if existing != payload and not replace:
                raise RuntimeError("a different release workflow exists; rerun with --replace to retain and supersede it")
            if existing == payload:
                state = "reused"
            else:
                SUPERSEDED.mkdir(parents=True, exist_ok=True)
                prior = SUPERSEDED / f"workflow.{digest(existing).removeprefix('sha256:')}.json"
                if prior.exists() and prior.read_bytes() != existing:
                    raise RuntimeError("superseded manifest identity conflict")
                if not prior.exists():
                    prior.write_bytes(existing)
                atomic_write(OUTPUT, payload)
                state = "superseded"
        else:
            atomic_write(OUTPUT, payload)
            state = "created"
        if OUTPUT.read_bytes() != payload:
            raise RuntimeError("materialized manifest bytes differ")
    return {
        "schema_version": "incidentseal-release-workflow-materialization/v1",
        "verification_verdict": "PASS",
        "state": state,
        "path": str(OUTPUT),
        "workflow_id": WORKFLOW_ID,
        "manifest_digest": manifest_digest,
        "repository_commit": commit,
        "repository_tree_digest": tree_digest,
        "approval_written": False,
        "check_only": check_only,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.check and args.replace:
        parser.error("--check and --replace are mutually exclusive")
    try:
        print(json.dumps(materialize(check_only=args.check, replace=args.replace), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-release-workflow-materialization/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_RELEASE_WORKFLOW_MATERIALIZATION", "message": str(error)},
            "approval_written": False,
        }, sort_keys=True, separators=(",", ":")))
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
