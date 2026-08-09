#!/usr/bin/env python3
"""Prove that security-relevant topology mutations fail closed without Docker."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = Path(__file__).resolve().with_name("validate_topology_contract.py")
LOCKED_FILES = (
    "contracts/topology-v1.json",
    "schemas/topology-contract-v1.schema.json",
    "schemas/topology-render-v1.schema.json",
    "fixtures/topology/render.valid.json",
    "fixtures/topology/mutations.json",
    "requirements/images.lock.json",
)


def sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def set_pointer(document: Any, pointer: str, value: Any) -> None:
    if not pointer.startswith("/"):
        raise ValueError(f"unsupported JSON pointer: {pointer}")
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]
    target = document
    for token in tokens[:-1]:
        target = target[int(token)] if isinstance(target, list) else target[token]
    final = tokens[-1]
    if isinstance(target, list):
        target[int(final)] = copy.deepcopy(value)
    else:
        target[final] = copy.deepcopy(value)


def copy_fixture_root(destination: Path) -> None:
    for directory in ("contracts", "schemas"):
        shutil.copytree(ROOT / directory, destination / directory)
    (destination / "fixtures").mkdir(parents=True)
    shutil.copytree(ROOT / "fixtures" / "topology", destination / "fixtures" / "topology")
    (destination / "requirements").mkdir(parents=True)
    shutil.copy2(ROOT / "requirements" / "images.lock.json", destination / "requirements" / "images.lock.json")
    shutil.copy2(
        ROOT / "requirements" / "topology-contract.lock.json",
        destination / "requirements" / "topology-contract.lock.json",
    )


def refresh_bindings(root: Path, target: str) -> None:
    if target == "contract":
        render_path = root / "fixtures" / "topology" / "render.valid.json"
        render = json.loads(render_path.read_text(encoding="utf-8"))
        render["contract_digest"] = sha256_file(root / "contracts" / "topology-v1.json")
        write_json(render_path, render)
    lock_path = root / "requirements" / "topology-contract.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    by_path = {item["path"]: item for item in lock["files"]}
    for relative in LOCKED_FILES:
        by_path[relative]["sha256"] = sha256_file(root / relative)
    write_json(lock_path, lock)


def invoke(root: Path) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), "--root", str(root)],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    stdout = completed.stdout.strip()
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"validator did not emit JSON: {stdout!r}; stderr={completed.stderr!r}") from error
    return completed.returncode, result, completed.stderr.strip()


def main() -> int:
    mutations_path = ROOT / "fixtures" / "topology" / "mutations.json"
    mutation_set = json.loads(mutations_path.read_text(encoding="utf-8"))
    mutations = mutation_set["mutations"]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-topology-mutations-") as temporary:
        base = Path(temporary) / "base"
        copy_fixture_root(base)
        baseline_code, baseline, baseline_stderr = invoke(base)
        if baseline_code != 0 or baseline.get("verdict") != "PASS":
            raise RuntimeError(f"baseline failed: {baseline}; stderr={baseline_stderr}")
        for index, mutation in enumerate(mutations):
            case_root = Path(temporary) / f"case-{index:02d}"
            shutil.copytree(base, case_root)
            target_relative = (
                "contracts/topology-v1.json"
                if mutation["target"] == "contract"
                else "fixtures/topology/render.valid.json"
            )
            target_path = case_root / target_relative
            document = json.loads(target_path.read_text(encoding="utf-8"))
            set_pointer(document, mutation["pointer"], mutation["value"])
            write_json(target_path, document)
            refresh_bindings(case_root, mutation["target"])
            code, result, stderr = invoke(case_root)
            actual = result.get("error", {}).get("code")
            passed = code != 0 and result.get("verdict") == "FAIL" and actual == mutation["expected_error"]
            results.append(
                {
                    "id": mutation["id"],
                    "expected_error": mutation["expected_error"],
                    "actual_error": actual,
                    "verdict": "PASS" if passed else "FAIL",
                }
            )
            if not passed:
                raise RuntimeError(f"mutation {mutation['id']} did not fail as expected: {result}; stderr={stderr}")
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-topology-mutation-results/v1",
                "verdict": "PASS",
                "mutations": results,
                "runtime_started": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
