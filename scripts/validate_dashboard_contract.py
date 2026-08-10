#!/usr/bin/env python3
"""Validate the exact dependency-free dashboard and evaluation contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.dashboard_contract import (  # noqa: E402
    DashboardContractError,
    EXPECTED_RECORDS,
    validate_corpus,
    validate_snapshot,
)
from incidentseal.manifest import strict_load_bytes  # noqa: E402


LOCK = ROOT / "requirements" / "dashboard-contract.lock.json"
SNAPSHOT = ROOT / "fixtures" / "dashboard" / "snapshot.valid.json"
CORPUS = ROOT / "fixtures" / "dashboard" / "scenario-corpus.valid.json"
MUTATIONS = ROOT / "fixtures" / "dashboard" / "contract-mutations.json"

EXPECTED_PATHS = (
    "docs/dashboard-contract.md",
    "docs/dashboard-evaluation-contract.md",
    "docs/dashboard-mutation-plan.md",
    "docs/dashboard-visual-acceptance.md",
    "docs/decisions/ADR-0010-read-only-dashboard-projection.md",
    "fixtures/dashboard/contract-mutations.json",
    "fixtures/dashboard/scenario-corpus.invalid.minimal.json",
    "fixtures/dashboard/scenario-corpus.valid.json",
    "fixtures/dashboard/snapshot.invalid.minimal.json",
    "fixtures/dashboard/snapshot.valid.json",
    "requirements/meta-validation.lock",
    "schemas/dashboard-scenario-corpus-v1.schema.json",
    "schemas/dashboard-snapshot-v1.schema.json",
    "scripts/run_dashboard_meta_validation.py",
    "scripts/test_dashboard_contract_mutations.py",
    "scripts/validate_dashboard_contract.py",
    "scripts/validate_dashboard_schema_meta.py",
    "src/incidentseal/dashboard_contract.py",
    "src/incidentseal/manifest.py",
    "tests/test_dashboard_contract.py",
)


def load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_lock() -> str:
    lock = load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-dashboard-contract-lock/v1":
        raise DashboardContractError("IS_DASHBOARD_LOCK", "dashboard contract lock version differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        raise DashboardContractError("IS_DASHBOARD_LOCK", "dashboard contract lock scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            raise DashboardContractError("IS_DASHBOARD_LOCK", f"dashboard contract lock drift: {item.get('path')}")
    bindings = lock.get("checkpoint_source_records")
    if not isinstance(bindings, list) or tuple((item.get("path"), item.get("kind")) for item in bindings if isinstance(item, dict)) != EXPECTED_RECORDS:
        raise DashboardContractError("IS_DASHBOARD_LOCK", "dashboard checkpoint source bindings differ")
    for item in bindings:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            raise DashboardContractError("IS_DASHBOARD_LOCK", f"dashboard source binding drift: {item.get('path')}")
    if lock.get("runtime_dependencies") != [] or lock.get("runtime_started") is not False:
        raise DashboardContractError("IS_DASHBOARD_LOCK", "contract validation gained runtime")
    if lock.get("server_started") is not False or lock.get("browser_started") is not False or lock.get("docker_started") is not False:
        raise DashboardContractError("IS_DASHBOARD_LOCK", "U01 started a forbidden product surface")
    return digest(LOCK)


def validate() -> dict[str, Any]:
    lock_digest = validate_lock()
    snapshot = validate_snapshot(load(SNAPSHOT), ROOT)
    corpus = validate_corpus(load(CORPUS))
    mutations = load(MUTATIONS)
    if not isinstance(mutations, dict) or mutations.get("schema_version") != "incidentseal-dashboard-contract-mutations/v1":
        raise DashboardContractError("IS_DASHBOARD_LOCK", "dashboard mutation manifest differs")
    mutation_count = len(mutations.get("mutations", []))
    return {
        "schema_version": "incidentseal-dashboard-contract-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": lock_digest,
        "snapshot_digest": snapshot["snapshot_digest"],
        "corpus_digest": corpus["corpus_digest"],
        "source_record_count": len(snapshot["source_records"]),
        "exit_count": len(snapshot["exits"]),
        "scenario_count": len(corpus["scenarios"]),
        "repetitions": corpus["repetitions"],
        "mutation_count": mutation_count,
        "runtime_started": False,
        "server_started": False,
        "browser_started": False,
        "docker_started": False,
        "third_party_runtime_dependencies": 0,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, DashboardContractError) else "IS_DASHBOARD_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-contract-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
