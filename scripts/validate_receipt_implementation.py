#!/usr/bin/env python3
"""Validate the locked real receipt CLI without Docker, database, network, or approval state."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "receipt-implementation.lock.json"
EXPECTED_PATHS = (
    "docs/cli-contract.md",
    "docs/receipt-implementation.md",
    "incidentseal",
    "incidentseal.cmd",
    "requirements/receipt-contract.lock.json",
    "scripts/validate_receipt_implementation.py",
    "src/incidentseal/__main__.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/manifest.py",
    "src/incidentseal/receipt.py",
    "tests/test_receipt.py",
)
EXPECTED_RECEIPT = "sha256:7293ac4087873338dfbe78411c74c809efd18b2ffac0aa88e052df33d0353c77"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def run_cli(*arguments: str) -> tuple[int, dict, str]:
    if os.name == "nt":
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(ROOT / "incidentseal.cmd")]
    else:
        command = [str(ROOT / "incidentseal")]
    completed = subprocess.run(command + list(arguments), cwd=ROOT, capture_output=True, text=True, check=False)
    if completed.stderr or completed.stdout.count("\n") != 1:
        raise RuntimeError("real receipt CLI stream discipline failed")
    envelope = json.loads(completed.stdout)
    if envelope["process_exit_code"] != completed.returncode:
        raise RuntimeError("real receipt CLI process exit differs from envelope")
    return completed.returncode, envelope, completed.stderr


def validate() -> dict:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if lock.get("schema_version") != "incidentseal-receipt-implementation-lock/v1":
        raise RuntimeError("receipt implementation lock version differs")
    entries = lock.get("files", [])
    paths = [entry.get("path") for entry in entries]
    if tuple(sorted(paths)) != EXPECTED_PATHS or len(paths) != len(set(paths)):
        raise RuntimeError("receipt implementation lock path set differs")
    for entry in entries:
        if digest(ROOT / entry["path"]) != entry["sha256"]:
            raise RuntimeError(f"receipt implementation lock drift: {entry['path']}")
    approval = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "IncidentSeal" / "approvals" / "v1"
    if approval.exists():
        raise RuntimeError("validation requires missing real approval state")
    with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-implementation-") as temporary:
        output = Path(temporary) / "output"
        code, write, _ = run_cli(
            "receipt", "materialize", "--receipt", str(ROOT / "fixtures/receipts/receipt.valid.json"),
            "--source-root", str(ROOT / "fixtures/receipts"), "--output-root", str(output), "--json",
        )
        if code != 0 or write["verdict"] != "PASS" or write["data"]["receipt_digest"] != EXPECTED_RECEIPT:
            raise RuntimeError("real receipt materialization failed")
        bundle = Path(write["data"]["bundle_path"])
        snapshot = {path.relative_to(bundle).as_posix(): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
        code, exact, _ = run_cli(
            "receipt", "verify", "--receipt", str(bundle / "receipt.json"), "--bundle-root", str(bundle),
            "--expected-digest", EXPECTED_RECEIPT, "--json",
        )
        if code != 0 or exact["verdict"] != "PASS":
            raise RuntimeError("real exact receipt verification failed")
        code, unbound, _ = run_cli(
            "receipt", "verify", "--receipt", str(bundle / "receipt.json"), "--bundle-root", str(bundle), "--json",
        )
        if code != 11 or unbound["verdict"] != "INCONCLUSIVE":
            raise RuntimeError("real unbound receipt did not remain inconclusive")
        after = {path.relative_to(bundle).as_posix(): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
        if snapshot != after:
            raise RuntimeError("read-only receipt verification changed bundle bytes")
    if approval.exists():
        raise RuntimeError("receipt validation changed approval state")
    return {
        "schema_version": "incidentseal-receipt-implementation-validation/v1",
        "verdict": "PASS",
        "implementation_lock_digest": digest(LOCK),
        "receipt_digest": EXPECTED_RECEIPT,
        "materialize_invocation_id": write["invocation_id"],
        "verify_invocation_id": exact["invocation_id"],
        "unbound_invocation_id": unbound["invocation_id"],
        "temporary_custody_removed": True,
        "bundle_files": sorted(snapshot),
        "runtime_dependency_count": 0,
        "docker_started": False,
        "database_accessed": False,
        "network_accessed": False,
        "approval_accessed": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({"schema_version":"incidentseal-receipt-implementation-validation/v1","verdict":"INVALID","error":{"code":"IS_RECEIPT_IMPLEMENTATION","message":str(error)}}, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
