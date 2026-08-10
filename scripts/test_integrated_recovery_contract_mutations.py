#!/usr/bin/env python3
"""Require every bounded integrated receipt/recovery mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.integrated_recovery import (  # noqa: E402
    IntegratedRecoveryError,
    matrix_digest,
    validate_matrix,
)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def case(value: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(item for item in value["cases"] if item["id"] == case_id)


def unknown(value: dict[str, Any]) -> None: value["unexpected"] = True
def authority(value: dict[str, Any]) -> None: value["authority"]["mode"] = "approved-workflow"
def workflow(value: dict[str, Any]) -> None: value["authority"]["workflow_executed"] = True
def socket(value: dict[str, Any]) -> None: value["custody"]["docker_socket_in_containers"] = True
def secret(value: dict[str, Any]) -> None: value["custody"]["container_secrets"] = True
def network(value: dict[str, Any]) -> None: value["custody"]["external_runtime_network"] = True
def protected_mount(value: dict[str, Any]) -> None: value["custody"]["protected_volumes_mounted"] = True
def repository_custody(value: dict[str, Any]) -> None: value["custody"]["temporary_custody"] = "repository"
def one_repeat(value: dict[str, Any]) -> None: value["composition"]["repetitions"] = 1
def remove_stage(value: dict[str, Any]) -> None: value["composition"]["stage_order"].pop()
def reorder_stage(value: dict[str, Any]) -> None: value["composition"]["stage_order"][0:2] = reversed(value["composition"]["stage_order"][0:2])
def arbitrary(value: dict[str, Any]) -> None: value["composition"]["arbitrary_arguments"] = True
def unbound_pass(value: dict[str, Any]) -> None: case(value, "receipt-unbound-identity")["expected_observation_verdict"] = "PASS"
def corruption_pass(value: dict[str, Any]) -> None: case(value, "receipt-corrupt-artifact")["expected_observation_verdict"] = "PASS"
def invalid_fail(value: dict[str, Any]) -> None: case(value, "receipt-invalid-identity")["expected_observation_verdict"] = "FAIL"
def fail_lifecycle(value: dict[str, Any]) -> None: case(value, "reliability-completed-fail")["expected_lifecycle"] = "failed"
def cancelled_verdict(value: dict[str, Any]) -> None: case(value, "reliability-host-cancelled")["expected_run_verdict"] = "FAIL"
def failed_verdict(value: dict[str, Any]) -> None: case(value, "reliability-database-outage")["expected_run_verdict"] = "FAIL"
def stale_verdict(value: dict[str, Any]) -> None: case(value, "journal-stale")["expected_run_verdict"] = "FAIL"
def remove_superseded(value: dict[str, Any]) -> None: value["cases"].remove(case(value, "journal-superseded"))
def ambiguous_pass(value: dict[str, Any]) -> None: case(value, "recovery-ambiguous-effects")["expected_observation_verdict"] = "PASS"
def conflict_pass(value: dict[str, Any]) -> None: case(value, "recovery-conflicting-effects")["expected_observation_verdict"] = "PASS"
def raw_stable(value: dict[str, Any]) -> None: value["cross_cycle"]["archive_identity_mode"] = "stable-raw-archive"
def toc_unstable(value: dict[str, Any]) -> None: value["cross_cycle"]["same_normalized_toc"] = False
def restore_unstable(value: dict[str, Any]) -> None: value["cross_cycle"]["same_restored_state"] = False
def protected_change(value: dict[str, Any]) -> None: value["cross_cycle"]["protected_volumes_unchanged"] = False
def teardown_off(value: dict[str, Any]) -> None: value["cross_cycle"]["teardown_between_stages"] = False
def digest_tamper(value: dict[str, Any]) -> None: value["matrix_digest"] = "sha256:" + "9" * 64


MUTATORS: dict[str, Callable[[dict[str, Any]], None]] = {
    "unknown-matrix-field": unknown,
    "workflow-authority-smuggled": authority,
    "workflow-execution-enabled": workflow,
    "container-docker-socket": socket,
    "container-secret": secret,
    "external-runtime-network": network,
    "protected-volume-mounted": protected_mount,
    "repository-temporary-custody": repository_custody,
    "single-repetition": one_repeat,
    "stage-removed": remove_stage,
    "stage-reordered": reorder_stage,
    "arbitrary-arguments-enabled": arbitrary,
    "receipt-unbound-promoted": unbound_pass,
    "receipt-corruption-promoted": corruption_pass,
    "receipt-invalid-collapsed": invalid_fail,
    "completed-fail-collapsed-to-failed": fail_lifecycle,
    "cancelled-run-gains-verdict": cancelled_verdict,
    "failed-run-gains-verdict": failed_verdict,
    "stale-run-gains-verdict": stale_verdict,
    "superseded-case-removed": remove_superseded,
    "ambiguous-recovery-promoted": ambiguous_pass,
    "conflicting-recovery-promoted": conflict_pass,
    "raw-archive-forced-stable": raw_stable,
    "normalized-toc-not-stable": toc_unstable,
    "restored-state-not-stable": restore_unstable,
    "protected-volume-change-allowed": protected_change,
    "interstage-teardown-disabled": teardown_off,
    "matrix-digest-tampered": digest_tamper,
}


def main() -> int:
    golden = load(ROOT / "fixtures" / "integrated-recovery" / "matrix.valid.json")
    manifest = load(ROOT / "fixtures" / "integrated-recovery" / "mutations.json")
    if tuple(MUTATORS) != tuple(item["id"] for item in manifest["mutations"]):
        raise RuntimeError("integrated recovery mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        value = deepcopy(golden)
        MUTATORS[item["id"]](value)
        if item["id"] != "matrix-digest-tampered":
            value["matrix_digest"] = matrix_digest(value)
        code = None
        try:
            validate_matrix(value)
        except IntegratedRecoveryError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({"id":item["id"],"expected_error":item["expected_error"],"actual_error":code,"verification_verdict":"PASS" if passed else "FAIL"})
        if not passed:
            raise RuntimeError(f"mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({"schema_version":"incidentseal-integrated-recovery-mutation-results/v1","verification_verdict":"PASS","mutation_count":len(results),"mutations":results,"runtime_started":False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
