#!/usr/bin/env python3
"""Validate the exact repeated-dashboard evaluator lock without starting runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_evaluation import DashboardEvaluationError  # noqa: E402
from incidentseal.manifest import strict_load_bytes  # noqa: E402
from scripts.validate_dashboard_browser import validate as validate_browser  # noqa: E402
from scripts.validate_dashboard_contract import validate as validate_contract  # noqa: E402
from scripts.validate_dashboard_implementation import validate as validate_implementation  # noqa: E402


LOCK = ROOT / "requirements" / "dashboard-evaluation.lock.json"
EXPECTED_PATHS = (
    "AGENTS.md",
    "docs/dashboard-repeated-evaluation.md",
    "fixtures/dashboard/evaluation-mutations.json",
    "scripts/run_dashboard_evaluation.py",
    "scripts/test_dashboard_evaluation_mutations.py",
    "scripts/validate_dashboard_evaluation.py",
    "src/incidentseal/dashboard_evaluation.py",
    "tests/test_dashboard_evaluation.py",
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def validate() -> dict[str, Any]:
    lock = _load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-dashboard-evaluation-lock/v1":
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_LOCK", "evaluation lock version differs")
    if lock.get("evaluation_id") != "INCIDENTSEAL-DASHBOARD-EVALUATION-001" or lock.get("revision") != 1:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_LOCK", "evaluation lock identity differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_LOCK", "evaluation lock scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or _digest(path) != item.get("sha256"):
            raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_LOCK", f"evaluation lock drift: {item.get('path')}")
    contract = validate_contract()
    implementation = validate_implementation()
    browser = validate_browser()
    expected_bindings = {
        "contract_lock": {"path": "requirements/dashboard-contract.lock.json", "sha256": contract["lock_digest"]},
        "implementation_lock": {"path": "requirements/dashboard-implementation.lock.json", "sha256": implementation["lock_digest"]},
        "browser_lock": {"path": "requirements/dashboard-browser.lock.json", "sha256": browser["lock_digest"]},
    }
    if lock.get("bindings") != expected_bindings:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_IDENTITY", "evaluation lock bindings differ")
    expected_plan = {
        "scenarios": 9,
        "repetitions": 3,
        "trials": 27,
        "routes_per_trial": 5,
        "metrics": [
            "case_correctness", "projection_latency_ms", "render_latency_ms",
            "peak_process_memory_bytes", "response_bytes", "request_failures",
            "source_record_coverage", "claim_calibration",
        ],
        "percentile_method": "nearest-rank",
        "browser_paint_measured": False,
        "performance_budget_enforced": False,
    }
    if lock.get("plan") != expected_plan:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_PLAN", "evaluation lock plan differs")
    if lock.get("runtime_dependencies") != []:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_DEPENDENCY", "evaluation lock gained runtime dependencies")
    if lock.get("static_validation_started_server") is not False or lock.get("docker_accessed") is not False:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_SECURITY", "static evaluation validation broadened runtime")
    return {
        "schema_version": "incidentseal-dashboard-evaluation-lock-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": _digest(LOCK),
        "contract_lock_digest": contract["lock_digest"],
        "implementation_lock_digest": implementation["lock_digest"],
        "browser_lock_digest": browser["lock_digest"],
        "scenarios": 9,
        "repetitions": 3,
        "trials": 27,
        "metrics": 8,
        "runtime_dependencies": 0,
        "server_started": False,
        "docker_accessed": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, DashboardEvaluationError) else "IS_DASHBOARD_EVALUATION_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-evaluation-lock-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
