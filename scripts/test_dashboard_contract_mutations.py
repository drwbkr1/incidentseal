#!/usr/bin/env python3
"""Require every bounded dashboard contract mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.dashboard_contract import (  # noqa: E402
    DashboardContractError,
    corpus_digest,
    snapshot_digest,
    validate_corpus,
    validate_snapshot,
)
from incidentseal.manifest import strict_load_bytes  # noqa: E402


def load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def scenario(value: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    return next(item for item in value["scenarios"] if item["id"] == scenario_id)


def unknown_snapshot(v: dict[str, Any]) -> None: v["unexpected"] = True
def checkpoint_tamper(v: dict[str, Any]) -> None: v["source"]["peeled_commit"] = "9" * 40
def record_hash(v: dict[str, Any]) -> None: v["source_records"][0]["sha256"] = "sha256:" + "9" * 64
def record_path(v: dict[str, Any]) -> None: v["source_records"][0]["path"] = "records/../AGENTS.md"
def record_remove(v: dict[str, Any]) -> None: v["source_records"].pop()
def approval(v: dict[str, Any]) -> None: v["authority"]["approval_status"] = "MATCH"
def workflow(v: dict[str, Any]) -> None: v["authority"]["workflow_executed"] = True
def creates_authority(v: dict[str, Any]) -> None: v["authority"]["dashboard_creates_authority"] = True
def non_loopback(v: dict[str, Any]) -> None: v["trust_boundary"]["bind_host"] = "0.0.0.0"
def write_method(v: dict[str, Any]) -> None: v["trust_boundary"]["allowed_methods"].append("POST")
def docker(v: dict[str, Any]) -> None: v["trust_boundary"]["docker_access"] = True
def approval_write(v: dict[str, Any]) -> None: v["trust_boundary"]["approval_write_access"] = True
def repository_write(v: dict[str, Any]) -> None: v["trust_boundary"]["repository_write_access"] = True
def network(v: dict[str, Any]) -> None: v["trust_boundary"]["external_network"] = True
def remote_assets(v: dict[str, Any]) -> None: v["trust_boundary"]["remote_assets"] = True
def analytics(v: dict[str, Any]) -> None: v["trust_boundary"]["analytics"] = True
def telemetry(v: dict[str, Any]) -> None: v["trust_boundary"]["telemetry"] = True
def remove_invalid(v: dict[str, Any]) -> None: del v["states"]["verification"]["INVALID"]
def remove_cancelled(v: dict[str, Any]) -> None: del v["states"]["lifecycle"]["cancelled"]
def remove_corrupt(v: dict[str, Any]) -> None: del v["states"]["corrupt_evidence"]
def snapshot_tamper(v: dict[str, Any]) -> None: v["snapshot_digest"] = "sha256:" + "9" * 64


def unknown_corpus(v: dict[str, Any]) -> None: v["unexpected"] = True
def remove_scenario(v: dict[str, Any]) -> None: v["scenarios"].pop()
def reorder_scenario(v: dict[str, Any]) -> None: v["scenarios"][0:2] = reversed(v["scenarios"][0:2])
def promote_missing(v: dict[str, Any]) -> None: scenario(v, "dashboard-missing-evidence")["claim_allowed"] = True
def policy_claim(v: dict[str, Any]) -> None: scenario(v, "dashboard-policy-attack")["claim_allowed"] = True
def isolation_claim(v: dict[str, Any]) -> None: scenario(v, "dashboard-isolation-attack")["claim_allowed"] = True
def promote_corrupt(v: dict[str, Any]) -> None: scenario(v, "dashboard-corrupt-receipt")["observation_verdict"] = "PASS"
def crash_verdict(v: dict[str, Any]) -> None: scenario(v, "dashboard-crash")["run_verdict"] = "FAIL"
def recovery_claim(v: dict[str, Any]) -> None: scenario(v, "dashboard-recovery")["claim_allowed"] = True
def one_repeat(v: dict[str, Any]) -> None: v["repetitions"] = 1
def external_request(v: dict[str, Any]) -> None: v["evaluation"]["external_requests"] = 1
def write_request(v: dict[str, Any]) -> None: v["evaluation"]["write_requests"] = 1
def false_pass(v: dict[str, Any]) -> None: v["evaluation"]["false_pass_limit"] = 1
def false_release(v: dict[str, Any]) -> None: v["evaluation"]["false_release_claim_limit"] = 1
def remove_metric(v: dict[str, Any]) -> None: v["evaluation"]["metrics"].pop()
def corpus_tamper(v: dict[str, Any]) -> None: v["corpus_digest"] = "sha256:" + "9" * 64


MUTATORS: dict[str, Callable[[dict[str, Any]], None]] = {
    "unknown-snapshot-field": unknown_snapshot,
    "checkpoint-commit-tampered": checkpoint_tamper,
    "record-hash-drift": record_hash,
    "record-path-unsafe": record_path,
    "record-removed": record_remove,
    "approval-promoted": approval,
    "workflow-executed": workflow,
    "dashboard-creates-authority": creates_authority,
    "non-loopback-bind": non_loopback,
    "write-method-added": write_method,
    "docker-access-added": docker,
    "approval-write-added": approval_write,
    "repository-write-added": repository_write,
    "external-network-added": network,
    "remote-assets-added": remote_assets,
    "analytics-added": analytics,
    "telemetry-added": telemetry,
    "invalid-verdict-state-removed": remove_invalid,
    "cancelled-lifecycle-state-removed": remove_cancelled,
    "corrupt-evidence-state-removed": remove_corrupt,
    "snapshot-digest-tampered": snapshot_tamper,
    "unknown-corpus-field": unknown_corpus,
    "scenario-removed": remove_scenario,
    "scenario-reordered": reorder_scenario,
    "missing-evidence-promoted": promote_missing,
    "policy-attack-claim-enabled": policy_claim,
    "isolation-attack-claim-enabled": isolation_claim,
    "corrupt-receipt-promoted": promote_corrupt,
    "crash-gains-verdict": crash_verdict,
    "recovery-claim-enabled": recovery_claim,
    "single-repetition": one_repeat,
    "external-request-allowed": external_request,
    "write-request-allowed": write_request,
    "false-pass-allowed": false_pass,
    "false-release-claim-allowed": false_release,
    "metric-removed": remove_metric,
    "corpus-digest-tampered": corpus_tamper,
}


def main() -> int:
    golden = {
        "snapshot": load(ROOT / "fixtures" / "dashboard" / "snapshot.valid.json"),
        "corpus": load(ROOT / "fixtures" / "dashboard" / "scenario-corpus.valid.json"),
    }
    manifest = load(ROOT / "fixtures" / "dashboard" / "contract-mutations.json")
    if tuple(MUTATORS) != tuple(item["id"] for item in manifest["mutations"]):
        raise RuntimeError("dashboard mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        target = item["target"]
        value = deepcopy(golden[target])
        MUTATORS[item["id"]](value)
        if target == "snapshot" and item["id"] != "snapshot-digest-tampered":
            value["snapshot_digest"] = snapshot_digest(value)
        if target == "corpus" and item["id"] != "corpus-digest-tampered":
            value["corpus_digest"] = corpus_digest(value)
        code = None
        try:
            validate_snapshot(value, ROOT) if target == "snapshot" else validate_corpus(value)
        except DashboardContractError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({
            "id": item["id"], "target": target, "expected_error": item["expected_error"],
            "actual_error": code, "verification_verdict": "PASS" if passed else "FAIL",
        })
        if not passed:
            raise RuntimeError(f"mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({
        "schema_version": "incidentseal-dashboard-contract-mutation-results/v1",
        "verification_verdict": "PASS", "mutation_count": len(results),
        "mutations": results, "runtime_started": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
