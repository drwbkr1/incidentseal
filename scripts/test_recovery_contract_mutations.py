#!/usr/bin/env python3
"""Require the frozen interruption-recovery contract to reject bounded mutations."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.recovery import RecoveryError, decide_recovery, validate_decision, validate_observation  # noqa: E402


def load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def mutate_decision(case: dict[str, Any], mutation: str) -> None:
    observation = deepcopy(case["observation"])
    decision = decide_recovery(observation)
    if mutation == "active-owner-resume":
        decision.update({"verification_verdict":"PASS","disposition":"resume","reason_code":"IS_RECOVERY_SAFE_REPLAY","replay_step":True,"next_phase":"dispatch"})
    elif mutation == "unowned-runtime-stop":
        decision.update({"verification_verdict":"PASS","disposition":"stop_then_reconcile","reason_code":"IS_RECOVERY_ORPHAN_RUNNING","process_action":"stop_owned_and_wait","next_phase":"reobserve"})
    elif mutation == "ambiguous-effects-promoted-pass":
        decision["verification_verdict"] = "PASS"
    elif mutation == "unsafe-replay-resume":
        decision.update({"verification_verdict":"PASS","disposition":"resume","reason_code":"IS_RECOVERY_SAFE_REPLAY","replay_step":True,"next_phase":"dispatch"})
    elif mutation in {"cancellation-run-verdict", "process-failure-run-verdict"}:
        decision["append"]["run_verdict"] = "PASS"
    elif mutation == "terminal-pair-drift":
        decision["append"]["terminal_lifecycle"] = "failed"
    elif mutation == "observation-digest-drift":
        decision["observation_digest"] = "sha256:" + "1" * 64
    elif mutation == "decision-digest-drift":
        decision["decision_digest"] = "sha256:" + "1" * 64
    elif mutation == "conflicting-effects-promoted-pass":
        decision["verification_verdict"] = "PASS"
    elif mutation in {"active-owner-evidence-write", "authority-unavailable-evidence-write"}:
        decision["append"]["evidence_event_type"] = "evidence.recorded"
    else:
        raise ValueError(f"unknown decision mutation: {mutation}")
    validate_decision(decision, observation)


def exercise(mutation: str, cases: dict[str, dict[str, Any]]) -> None:
    safe = deepcopy(cases["safe-replay-before-dispatch"]["observation"])
    if mutation == "unknown-observation-field":
        safe["unexpected"] = True
        validate_observation(safe)
    elif mutation == "journal-count-drift":
        safe["journal"]["event_count"] = 3
        validate_observation(safe)
    elif mutation == "journal-verdict-fabricated":
        safe["journal"]["verdict"] = "PASS"
        validate_observation(safe)
    elif mutation == "authority-match-drift":
        safe["authority"]["observed_approval_digest"] = "sha256:" + "1" * 64
        validate_observation(safe)
    elif mutation == "before-dispatch-effects":
        safe["effects"]["artifact"] = "matching"
        validate_observation(safe)
    elif mutation == "runtime-exit-code-drift":
        safe["runtime"]["process_exit_code"] = 1
        validate_observation(safe)
    elif mutation == "missing-lease-retains-fields":
        safe["lease"]["status"] = "missing"
        validate_observation(safe)
    elif mutation == "cancel-request-kind-drift":
        safe["request"] = "cancel"
        validate_observation(safe)
    else:
        case_by_mutation = {
            "active-owner-resume":"active-owner-defer",
            "unowned-runtime-stop":"unowned-orphan-defer",
            "ambiguous-effects-promoted-pass":"ambiguous-effects-defer",
            "unsafe-replay-resume":"unsafe-replay-defer",
            "cancellation-run-verdict":"confirmed-cancellation",
            "terminal-pair-drift":"confirmed-cancellation",
            "observation-digest-drift":"safe-replay-before-dispatch",
            "decision-digest-drift":"safe-replay-before-dispatch",
            "process-failure-run-verdict":"confirmed-process-failure",
            "conflicting-effects-promoted-pass":"conflicting-effects-fail",
            "active-owner-evidence-write":"active-owner-defer",
            "authority-unavailable-evidence-write":"authority-unavailable-defer",
        }
        mutate_decision(cases[case_by_mutation[mutation]], mutation)


def main() -> int:
    vectors = load(ROOT / "fixtures" / "recovery" / "vectors.json")
    cases = {case["id"]: case for case in vectors["cases"]}
    manifest = load(ROOT / "fixtures" / "recovery" / "mutations.json")
    results = []
    for mutation in manifest["mutations"]:
        try:
            exercise(mutation["id"], cases)
        except RecoveryError as error:
            actual = error.code
        else:
            actual = None
        passed = actual == mutation["expected_error"]
        results.append({"id":mutation["id"],"expected_error":mutation["expected_error"],"actual_error":actual,"verification_verdict":"PASS" if passed else "FAIL"})
        if not passed:
            raise RuntimeError(f"recovery mutation {mutation['id']} returned {actual}")
    print(json.dumps({"schema_version":"incidentseal-recovery-mutation-results/v1","verification_verdict":"PASS","mutation_count":len(results),"mutations":results,"runtime_started":False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
