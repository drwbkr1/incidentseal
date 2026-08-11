#!/usr/bin/env python3
"""Validate the exact runtime-free IS6-U02 workflow execution contract lock."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.workflow_contract import WorkflowContractError, validate_execution_contract  # noqa: E402

LOCK = ROOT / "requirements" / "workflow-verification-contract.lock.json"
CONTRACT = ROOT / "fixtures" / "workflow-verification" / "execution-contract.valid.json"
MUTATIONS = ROOT / "fixtures" / "workflow-verification" / "mutations.json"
RUNTIME_LOCK = ROOT / "requirements" / "topology-runtime.lock.json"
EXPECTED_PATHS = (
    "AGENTS.md",
    "docs/workflow-verification-contract.md",
    "docs/decisions/ADR-0012-bounded-python-node-workflow-profile.md",
    "fixtures/workflow-verification/execution-contract.invalid.minimal.json",
    "fixtures/workflow-verification/execution-contract.valid.json",
    "fixtures/workflow-verification/mutations.json",
    "schemas/workflow-execution-contract-v1.schema.json",
    "scripts/run_workflow_contract_meta_validation.py",
    "scripts/test_workflow_contract_mutations.py",
    "scripts/validate_workflow_contract.py",
    "scripts/validate_workflow_contract_lock.py",
    "scripts/validate_workflow_contract_schema_meta.py",
    "src/incidentseal/workflow_contract.py",
    "tests/test_workflow_contract.py",
)
BINDINGS = (
    "docs/product-contract.md",
    "docs/manifest-authority.md",
    "docs/cli-contract.md",
    "docs/threat-model.md",
    "schemas/workflow-manifest-v1.schema.json",
    "schemas/manifest-approval-v1.schema.json",
    "schemas/run-event-v1.schema.json",
    "schemas/portable-receipt-v1.schema.json",
    "requirements/topology-runtime.lock.json",
    "requirements/release-contract.lock.json",
    "requirements/meta-validation.lock",
    "records/source-gates/2026-08-09-jsonschema-meta-validation.json",
    "records/evaluations/IS-0006-U01-release-contract.json",
    "records/surface-receipts/IS-0006-U01-public-release-contract-replay.json",
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def _reject(message: str) -> None:
    raise WorkflowContractError("IS_WORKFLOW_LOCK", message)


def validate() -> dict[str, Any]:
    lock = _load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-workflow-verification-contract-lock/v1":
        _reject("workflow contract lock version differs")
    if lock.get("contract_id") != "INCIDENTSEAL-WORKFLOW-EXECUTION-001" or lock.get("revision") != 1:
        _reject("workflow contract lock identity differs")
    if lock.get("checkpoint_id") != "IS-0006" or lock.get("unit_id") != "IS6-U02":
        _reject("workflow contract milestone binding differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        _reject("workflow contract lock file scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or item.get("sha256") != _digest(path):
            _reject(f"workflow contract lock drift: {item.get('path')}")
    bindings = lock.get("bindings")
    if not isinstance(bindings, list) or tuple(item.get("path") for item in bindings if isinstance(item, dict)) != BINDINGS:
        _reject("workflow contract binding scope differs")
    for item in bindings:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or item.get("sha256") != _digest(path):
            _reject(f"workflow contract binding drift: {item.get('path')}")
    result = validate_execution_contract(_load(CONTRACT))
    if result["contract_digest"] != lock.get("contract", {}).get("canonical_digest"):
        _reject("workflow execution contract digest differs")
    mutations = _load(MUTATIONS)
    if len(mutations.get("mutations", [])) != 47 or lock.get("mutation_count") != 47:
        _reject("workflow mutation manifest differs")
    runtime = _load(RUNTIME_LOCK)
    roles = {item.get("role"): item.get("image_id") for item in runtime.get("images", []) if isinstance(item, dict)}
    if set(roles) != {"database", "migration", "python-runner", "node-runner"}:
        _reject("workflow runtime image roles differ")
    if any(not isinstance(value, str) or not value.startswith("sha256:") for value in roles.values()):
        _reject("workflow runtime image identity differs")
    static = lock.get("static_validation")
    expected_static = {
        "approval_written": False, "workflow_executed": False, "docker_accessed": False,
        "artifact_built": False, "package_built": False, "image_published": False,
        "release_published": False,
    }
    if static != expected_static:
        _reject("workflow contract static boundary differs")
    return {
        "schema_version":"incidentseal-workflow-verification-contract-lock-validation/v1",
        "verification_verdict":"PASS",
        "lock_digest":_digest(LOCK),
        "contract_digest":result["contract_digest"],
        "locked_files":len(files),
        "bindings":len(bindings),
        "mutations":47,
        "supported_runners":2,
        **static,
    }


def main() -> int:
    try:
        result = validate()
    except (OSError, ValueError, WorkflowContractError) as error:
        print(json.dumps({"schema_version":"incidentseal-workflow-verification-contract-lock-validation/v1","verification_verdict":"INVALID","error_code":getattr(error, "code", "IS_WORKFLOW_IO"),"error":str(error)}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
