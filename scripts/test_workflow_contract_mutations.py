#!/usr/bin/env python3
"""Apply every closed workflow-contract mutation and require fail-closed rejection."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.workflow_contract import WorkflowContractError, validate_execution_contract  # noqa: E402

FIXTURES = ROOT / "fixtures" / "workflow-verification"


def set_path(value: dict[str, object], dotted: str, replacement: object) -> None:
    parts = dotted.split(".")
    target: dict[str, object] = value
    for part in parts[:-1]:
        child = target.get(part)
        if not isinstance(child, dict):
            raise RuntimeError(f"mutation path is not an object: {dotted}")
        target = child
    target[parts[-1]] = replacement


def main() -> int:
    golden = strict_load_bytes((FIXTURES / "execution-contract.valid.json").read_bytes())
    manifest = strict_load_bytes((FIXTURES / "mutations.json").read_bytes())
    results: list[dict[str, str]] = []
    for mutation in manifest["mutations"]:
        candidate = deepcopy(golden)
        set_path(candidate, mutation["path"], mutation["value"])
        try:
            validate_execution_contract(candidate)
        except WorkflowContractError as error:
            if error.code != mutation["error_code"]:
                raise RuntimeError(f"{mutation['id']} returned {error.code}, expected {mutation['error_code']}") from error
            results.append({"id":mutation["id"],"status":"PASS","error_code":error.code})
        else:
            raise RuntimeError(f"mutation unexpectedly passed: {mutation['id']}")
    print(json.dumps({
        "schema_version":"incidentseal-workflow-execution-mutation-result/v1",
        "verification_verdict":"PASS",
        "mutations":len(results),
        "passed":len(results),
        "artifact_built":False,
        "docker_accessed":False,
        "workflow_executed":False,
        "results":results,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
