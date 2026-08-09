#!/usr/bin/env python3
"""Mutate the portable receipt implementation and require its validator to fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    old: str
    new: str
    refresh_lock: bool = True


MUTATIONS = (
    Mutation(
        "stale-runtime-source",
        '"""Atomic portable receipt materialization and read-only offline verification."""',
        '"""Mutated portable receipt materialization and read-only offline verification."""',
        refresh_lock=False,
    ),
    Mutation('unbound-promoted-to-pass', 'identity = "UNBOUND"\n        verdict = "INCONCLUSIVE"', 'identity = "UNBOUND"\n        verdict = "PASS"'),
    Mutation('identity-mismatch-promoted-to-pass', 'identity = "MISMATCH"\n        verdict = "INVALID"', 'identity = "MISMATCH"\n        verdict = "PASS"'),
    Mutation('missing-artifact-promoted-to-pass', 'status = "INCONCLUSIVE"', 'status = "PASS"'),
    Mutation('corrupt-artifact-promoted-to-pass', 'status = "FAIL"', 'status = "PASS"'),
    Mutation(
        'event-digest-check-bypassed',
        'if link["event_digest"] != event_digest:',
        'if False and link["event_digest"] != event_digest:',
    ),
    Mutation(
        'run-summary-check-bypassed',
        'if any(summary[name] != final[name] for name in ("lifecycle", "verdict", "terminal")):',
        'if False and any(summary[name] != final[name] for name in ("lifecycle", "verdict", "terminal")):',
    ),
    Mutation('repository-output-bypassed', 'if forbidden is not None:', 'if False and forbidden is not None:'),
    Mutation(
        'idempotent-state-drift',
        '"created": False, "idempotent": True, "verification": verified',
        '"created": True, "idempotent": False, "verification": verified',
    ),
    Mutation('corrupt-source-check-bypassed', 'if artifact_status != "PASS":', 'if False and artifact_status != "PASS":'),
    Mutation(
        'verify-runtime-lock-bypassed',
        'def verify_bundle(receipt_path: str | Path, bundle_root: str | Path, expected_digest: str | None) -> dict[str, Any]:\n    _validate_implementation_lock()',
        'def verify_bundle(receipt_path: str | Path, bundle_root: str | Path, expected_digest: str | None) -> dict[str, Any]:\n    pass  # mutation bypasses runtime lock',
    ),
    Mutation(
        'materialize-runtime-lock-bypassed',
        'def materialize_bundle(receipt_path: str | Path, source_root: str | Path, output_root: str | Path) -> dict[str, Any]:\n    _validate_implementation_lock()',
        'def materialize_bundle(receipt_path: str | Path, source_root: str | Path, output_root: str | Path) -> dict[str, Any]:\n    pass  # mutation bypasses runtime lock',
    ),
)


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def copy_root(destination: Path) -> None:
    lock_path = ROOT / "requirements" / "receipt-implementation.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    for entry in lock["files"]:
        relative = entry["path"]
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copy2(lock_path, destination / "requirements" / "receipt-implementation.lock.json")
    shutil.copytree(
        ROOT / "src" / "incidentseal",
        destination / "src" / "incidentseal",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(ROOT / "fixtures" / "receipts", destination / "fixtures" / "receipts")


def refresh_lock(root: Path) -> None:
    lock_path = root / "requirements" / "receipt-implementation.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entry = next(item for item in lock["files"] if item["path"] == "src/incidentseal/receipt.py")
    entry["sha256"] = sha256_file(root / entry["path"])
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")


def apply_mutation(root: Path, mutation: Mutation) -> None:
    path = root / "src" / "incidentseal" / "receipt.py"
    text = path.read_text(encoding="utf-8")
    count = text.count(mutation.old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count for {mutation.id} was {count}, expected 1")
    path.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8", newline="\n")
    if mutation.refresh_lock:
        refresh_lock(root)


def invoke(root: Path) -> tuple[int, dict[str, Any], str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-B", str(root / "scripts" / "validate_receipt_implementation.py")],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    if completed.stdout.count("\n") != 1 or not completed.stdout.endswith("\n"):
        raise RuntimeError(f"receipt mutation validator stream differed: {completed.stdout!r}")
    return completed.returncode, json.loads(completed.stdout), completed.stderr


def main() -> int:
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-mutations-") as temporary:
        base = Path(temporary) / "base"
        copy_root(base)
        baseline_code, baseline, baseline_stderr = invoke(base)
        if baseline_code != 0 or baseline.get("verdict") != "PASS" or baseline_stderr:
            raise RuntimeError(f"receipt mutation baseline failed: {baseline}; stderr={baseline_stderr}")
        for index, mutation in enumerate(MUTATIONS):
            case = Path(temporary) / f"case-{index:02d}"
            shutil.copytree(base, case)
            apply_mutation(case, mutation)
            code, envelope, stderr = invoke(case)
            actual = envelope.get("error", {}).get("code")
            passed = code != 0 and envelope.get("verdict") == "INVALID" and actual == "IS_RECEIPT_IMPLEMENTATION" and not stderr
            results.append(
                {
                    "id": mutation.id,
                    "expected_error": "IS_RECEIPT_IMPLEMENTATION",
                    "actual_error": actual,
                    "verdict": "PASS" if passed else "FAIL",
                }
            )
            if not passed:
                raise RuntimeError(f"mutation {mutation.id} failed incorrectly: {envelope}; stderr={stderr}")
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-receipt-implementation-mutations/v1",
                "verdict": "PASS",
                "mutation_count": len(results),
                "mutations": results,
                "runtime_started": False,
                "network_accessed": False,
                "approval_accessed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
