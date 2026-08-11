#!/usr/bin/env python3
"""Require every repeated-dashboard result mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_evaluation import (  # noqa: E402
    DashboardEvaluationError,
    run_evaluation,
    validate_result,
)
from incidentseal.manifest import strict_load_bytes  # noqa: E402
from scripts.validate_dashboard_evaluation import validate as validate_lock  # noqa: E402


Mutator = Callable[[dict[str, Any]], None]


def _set(*path: Any, value: Any) -> Mutator:
    def mutate(result: dict[str, Any]) -> None:
        current: Any = result
        for part in path[:-1]:
            current = current[part]
        current[path[-1]] = value
    return mutate


def _remove_trial(result: dict[str, Any]) -> None:
    result["trials"].pop()


def _reorder_trials(result: dict[str, Any]) -> None:
    result["trials"][0], result["trials"][1] = result["trials"][1], result["trials"][0]


MUTATORS: dict[str, Mutator] = {
    "evaluation-lock-changed": _set("identity", "evaluation_lock_digest", value="sha256:" + "0" * 64),
    "contract-lock-changed": _set("identity", "contract_lock_digest", value="sha256:" + "0" * 64),
    "repetition-count-changed": _set("plan", "repetitions", value=2),
    "trial-removed": _remove_trial,
    "trial-order-changed": _reorder_trials,
    "scenario-kind-changed": _set("trials", 0, "kind", value="product-failure"),
    "failure-claim-permitted": _set("trials", 1, "claim_observed", value="permitted"),
    "missing-evidence-claim-permitted": _set("trials", 3, "claim_observed", value="permitted"),
    "crash-gains-verdict": _set("trials", 7, "run_verdict", value="FAIL"),
    "recovery-loses-observation": _set("trials", 8, "observation_verdict", value=None),
    "case-correctness-weakened": _set("trials", 0, "case_correct", value=False),
    "projection-latency-missing": _set("trials", 0, "projection_latency_ns", value=0),
    "render-latency-missing": _set("trials", 0, "render_latency_ns", value=0),
    "memory-missing": _set("trials", 0, "peak_process_memory_bytes", value=0),
    "response-bytes-missing": _set("trials", 0, "response_bytes", value=0),
    "request-failure-hidden": _set("trials", 0, "request_failures", value=1),
    "source-coverage-reduced": _set("trials", 0, "source_records_verified", value=6),
    "html-digest-instability": _set("trials", 0, "html_digest", value="sha256:" + "0" * 64),
    "trial-server-left-open": _set("trials", 0, "server_closed", value=False),
    "aggregate-metric-spoofed": _set("metrics", "case_correctness", "correct", value=26),
    "recovery-transition-spoofed": _set("recovery", "crash_recovery_transitions", value=2),
    "external-request-added": _set("security_boundary", "external_requests", value=1),
    "docker-access-added": _set("security_boundary", "docker_accessed", value=True),
    "workflow-execution-added": _set("security_boundary", "workflow_executed", value=True),
    "repository-write-added": _set("security_boundary", "repository_writes", value=1),
    "server-process-retained": _set("runtime_boundary", "server_processes_after", value=1),
    "browser-paint-misclaimed": _set("scope", "browser_paint_measured", value=True),
    "runtime-dependency-added": _set("runtime_dependencies", value=["psutil"]),
    "non-claim-removed": lambda result: result["non_claims"].pop(),
    "pass-verdict-rewritten": _set("verification_verdict", value="FAIL"),
}


def main() -> int:
    lock = validate_lock()
    golden = run_evaluation(lock["lock_digest"])
    manifest = strict_load_bytes((ROOT / "fixtures" / "dashboard" / "evaluation-mutations.json").read_bytes())
    if not isinstance(manifest, dict) or tuple(MUTATORS) != tuple(item["id"] for item in manifest.get("mutations", [])):
        raise RuntimeError("dashboard evaluation mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        candidate = deepcopy(golden)
        MUTATORS[item["id"]](candidate)
        code = None
        try:
            validate_result(candidate, evaluation_lock_digest=lock["lock_digest"])
        except DashboardEvaluationError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({
            "id": item["id"], "expected_error": item["expected_error"], "actual_error": code,
            "verification_verdict": "PASS" if passed else "FAIL",
        })
        if not passed:
            raise RuntimeError(f"evaluation mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({
        "schema_version": "incidentseal-dashboard-evaluation-mutation-results/v1",
        "verification_verdict": "PASS",
        "mutation_count": len(results),
        "mutations": results,
        "trials_executed": 27,
        "loopback_servers_started": 27,
        "loopback_servers_after": 0,
        "docker_accessed": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
