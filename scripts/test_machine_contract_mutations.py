#!/usr/bin/env python3
"""Prove that bounded mutations make the machine-contract validator fail closed."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def run_validator(test_root: Path) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(test_root / "scripts" / "validate_machine_contracts.py")],
        cwd=test_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"validator returned non-JSON stdout: {completed.stdout!r}") from error
    return completed.returncode, result


def make_test_root(parent: Path, name: str) -> Path:
    test_root = parent / name
    (test_root / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "validate_machine_contracts.py", test_root / "scripts")
    shutil.copytree(ROOT / "schemas", test_root / "schemas")
    shutil.copytree(ROOT / "fixtures", test_root / "fixtures")
    return test_root


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"mutation target count for {path.name} was {text.count(old)}, expected 1")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def main() -> int:
    mutations = [
        {
            "id": "uncontrolled-schema-id",
            "path": Path("schemas/workflow-manifest-v1.schema.json"),
            "old": "https://raw.githubusercontent.com/drwbkr1/incidentseal/main/schemas/",
            "new": "https://example.invalid/schemas/",
            "expected_error": "IS_SCHEMA_DOCUMENT",
        },
        {
            "id": "unknown-exit-code",
            "path": Path("fixtures/contracts/cli-envelope.valid.json"),
            "old": '"process_exit_code": 0',
            "new": '"process_exit_code": 9',
            "expected_error": "IS_SCHEMA_INSTANCE",
        },
        {
            "id": "golden-digest-drift",
            "path": Path("fixtures/contracts/canonicalization-vectors.json"),
            "old": "0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45",
            "new": "1448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45",
            "expected_error": "IS_CONTRACT_FIXTURE",
        },
        {
            "id": "verdict-lifecycle-drift",
            "path": Path("fixtures/contracts/run-event.valid.json"),
            "old": '"lifecycle": "completed"',
            "new": '"lifecycle": "failed"',
            "expected_error": "IS_CONTRACT_FIXTURE",
        },
    ]

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-u01-") as temporary:
        temp_parent = Path(temporary)
        baseline_root = make_test_root(temp_parent, "baseline")
        baseline_code, baseline = run_validator(baseline_root)
        if baseline_code != 0 or baseline.get("status") != "PASS":
            raise RuntimeError(f"baseline validator failed: {baseline}")
        results.append({"id": "baseline", "status": "PASS", "exit_code": baseline_code})

        for mutation in mutations:
            test_root = make_test_root(temp_parent, mutation["id"])
            replace_once(test_root / mutation["path"], mutation["old"], mutation["new"])
            exit_code, result = run_validator(test_root)
            error_code = result.get("error", {}).get("code")
            passed = (
                exit_code != 0
                and result.get("status") == "FAIL"
                and error_code == mutation["expected_error"]
            )
            results.append(
                {
                    "id": mutation["id"],
                    "status": "PASS" if passed else "FAIL",
                    "validator_exit_code": exit_code,
                    "observed_error": error_code,
                    "expected_error": mutation["expected_error"],
                }
            )

    overall = "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL"
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-machine-contract-mutations/v1",
                "status": overall,
                "mutations": results,
                "third_party_dependencies": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-machine-contract-mutations/v1",
                    "status": "FAIL",
                    "error": {"code": "IS_MUTATION_HARNESS", "message": str(error)},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        sys.exit(1)
