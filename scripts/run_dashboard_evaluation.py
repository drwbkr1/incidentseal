#!/usr/bin/env python3
"""Run the fixed 27-trial dashboard evaluation and emit one JSON document."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_evaluation import DashboardEvaluationError, run_evaluation  # noqa: E402
from scripts.validate_dashboard_evaluation import validate as validate_lock  # noqa: E402


def main() -> int:
    try:
        lock = validate_lock()
        result = run_evaluation(lock["lock_digest"])
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["verification_verdict"] == "PASS" else 10
    except Exception as error:
        code = error.code if isinstance(error, DashboardEvaluationError) else "IS_DASHBOARD_EVALUATION_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-repeated-evaluation/v1",
            "execution_state": "completed",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
