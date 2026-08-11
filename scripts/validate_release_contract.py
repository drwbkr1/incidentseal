#!/usr/bin/env python3
"""Validate the exact runtime-free IS6-U01 release-contract lock."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.release_contract import ReleaseContractError, validate_release_plan  # noqa: E402


LOCK = ROOT / "requirements" / "release-contract.lock.json"
PLAN = ROOT / "fixtures" / "release" / "release-plan.valid.json"
SOURCE_GATE = ROOT / "records" / "source-gates" / "2026-08-11-release-tooling.json"
EXPECTED_PATHS = (
    "AGENTS.md",
    "docs/release-contract.md",
    "docs/decisions/ADR-0011-approved-workflow-before-portable-release.md",
    "fixtures/release/mutations.json",
    "fixtures/release/release-plan.invalid.minimal.json",
    "fixtures/release/release-plan.valid.json",
    "records/source-gates/2026-08-11-release-tooling.json",
    "schemas/release-plan.v1.schema.json",
    "scripts/run_release_meta_validation.py",
    "scripts/test_release_contract_mutations.py",
    "scripts/validate_release_contract.py",
    "scripts/validate_release_plan.py",
    "scripts/validate_release_schema_meta.py",
    "src/incidentseal/release_contract.py",
    "tests/test_release_contract.py",
)
BINDINGS = (
    "docs/product-contract.md",
    "docs/threat-model.md",
    "requirements/images.lock.json",
    "requirements/topology-runtime.lock.json",
    "requirements/meta-validation.lock",
    "records/evaluations/IS-0005-U05-public-checkpoint.json",
    "records/surface-receipts/IS-0005-public-checkpoint.json",
    "records/surface-receipts/IS-0005-checkpoint-marker.json",
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def _reject(code: str, message: str) -> None:
    raise ReleaseContractError(code, message)


def validate() -> dict[str, Any]:
    lock = _load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-release-contract-lock/v1":
        _reject("IS_RELEASE_LOCK", "release lock version differs")
    if lock.get("contract_id") != "INCIDENTSEAL-RELEASE-001" or lock.get("revision") != 1:
        _reject("IS_RELEASE_LOCK", "release lock identity differs")
    if lock.get("checkpoint_id") != "IS-0006" or lock.get("unit_id") != "IS6-U01":
        _reject("IS_RELEASE_LOCK", "release lock milestone binding differs")

    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        _reject("IS_RELEASE_LOCK", "release lock file scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or item.get("sha256") != _digest(path):
            _reject("IS_RELEASE_LOCK", f"release lock drift: {item.get('path')}")

    bindings = lock.get("bindings")
    if not isinstance(bindings, list) or tuple(item.get("path") for item in bindings if isinstance(item, dict)) != BINDINGS:
        _reject("IS_RELEASE_IDENTITY", "release binding scope differs")
    for item in bindings:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or item.get("sha256") != _digest(path):
            _reject("IS_RELEASE_IDENTITY", f"release binding drift: {item.get('path')}")

    plan_result = validate_release_plan(_load(PLAN))
    expected_plan = {
        "path": "fixtures/release/release-plan.valid.json",
        "canonical_digest": plan_result["plan_digest"],
        "version": "0.1.0",
        "workflow_verification_required": True,
        "package_artifacts": 2,
        "release_assets": 9,
        "image_roles": 4,
        "real_surfaces": 13,
        "github_actions": 8,
        "human_gates": 1,
        "released": False,
    }
    if lock.get("plan") != expected_plan:
        _reject("IS_RELEASE_PLAN", "release lock plan projection differs")

    gate = _load(SOURCE_GATE)
    if not isinstance(gate, dict) or gate.get("assessment_id") != "INCIDENTSEAL-SOURCE-GATE-RELEASE-001":
        _reject("IS_RELEASE_SOURCE_GATE", "release tooling source gate identity differs")
    if gate.get("decision", {}).get("status") != "PASS_CONDITIONAL":
        _reject("IS_RELEASE_SOURCE_GATE", "release tooling source gate is not conditional PASS")
    if len(gate.get("python_build_wheels", [])) != 9 or len(gate.get("github_actions", [])) != 8 or len(gate.get("standalone_tools", [])) != 2:
        _reject("IS_RELEASE_SOURCE_GATE", "release tooling source scope differs")
    if any(item.get("status") != "PASS" for item in gate.get("criteria", [])) or len(gate.get("criteria", [])) != 8:
        _reject("IS_RELEASE_SOURCE_GATE", "release tooling source criteria differ")
    intended = gate.get("intended_use", {})
    if intended.get("runtime_dependencies_added") is not False or intended.get("artifact_acquired_by_this_gate") is not False or intended.get("container_started_by_this_gate") is not False or intended.get("publication_performed_by_this_gate") is not False:
        _reject("IS_RELEASE_SOURCE_GATE", "release tooling source gate broadened execution")

    expected_evaluation = {
        "meta_validation_lock": "requirements/meta-validation.lock",
        "meta_validation_source_gate": "records/source-gates/2026-08-09-jsonschema-meta-validation.json",
        "draft": "https://json-schema.org/draft/2020-12/schema",
        "schemas": 1,
        "fixtures": 2,
        "retained_exact_wheel_reuse": True,
        "runtime_dependency": False,
    }
    if lock.get("evaluation_dependencies") != expected_evaluation:
        _reject("IS_RELEASE_SCHEMA", "release schema evaluation binding differs")
    if lock.get("runtime_dependencies") != []:
        _reject("IS_RELEASE_DEPENDENCY", "release contract gained a runtime dependency")
    if lock.get("static_validation") != {
        "workflow_executed": False,
        "artifact_built": False,
        "docker_accessed": False,
        "image_published": False,
        "release_published": False,
        "github_setting_changed": False,
    }:
        _reject("IS_RELEASE_SECURITY", "release contract validation broadened runtime or publication")

    return {
        "schema_version": "incidentseal-release-contract-lock-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": _digest(LOCK),
        "plan_digest": plan_result["plan_digest"],
        "locked_files": len(EXPECTED_PATHS),
        "bindings": len(BINDINGS),
        "source_wheels": 9,
        "github_actions": 8,
        "standalone_tools": 2,
        "real_surfaces": 13,
        "workflow_verification_required": True,
        "runtime_dependencies": 0,
        "workflow_executed": False,
        "artifact_built": False,
        "docker_accessed": False,
        "published": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, ReleaseContractError) else "IS_RELEASE_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-release-contract-lock-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
