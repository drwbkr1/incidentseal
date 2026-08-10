from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.recovery import decide_recovery, validate_decision  # noqa: E402


class RecoveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {
            case["id"]: case
            for case in json.loads((ROOT / "fixtures/recovery/vectors.json").read_text(encoding="utf-8"))["cases"]
        }

    def test_all_frozen_decisions_validate_exactly(self) -> None:
        for case in self.cases.values():
            decision = decide_recovery(case["observation"])
            self.assertEqual(validate_decision(decision, case["observation"]), decision)

    def test_recovery_never_fabricates_a_run_verdict(self) -> None:
        for case in self.cases.values():
            self.assertIsNone(decide_recovery(case["observation"])["append"]["run_verdict"])

    def test_cancellation_and_failure_remain_distinct_lifecycles(self) -> None:
        cancelled = decide_recovery(self.cases["confirmed-cancellation"]["observation"])
        failed = decide_recovery(self.cases["confirmed-process-failure"]["observation"])
        self.assertEqual(cancelled["append"]["terminal_lifecycle"], "cancelled")
        self.assertEqual(failed["append"]["terminal_lifecycle"], "failed")
        self.assertEqual(cancelled["verification_verdict"], failed["verification_verdict"], "PASS")

    def test_ambiguous_or_unsafe_evidence_defers_inconclusively(self) -> None:
        for case_id in ("ambiguous-effects-defer", "unsafe-replay-defer", "authority-unavailable-defer"):
            decision = decide_recovery(self.cases[case_id]["observation"])
            self.assertEqual((decision["disposition"], decision["verification_verdict"]), ("defer", "INCONCLUSIVE"))

    def test_active_or_unowned_runtime_is_not_mutated(self) -> None:
        for case_id in ("active-owner-defer", "unowned-orphan-defer"):
            decision = decide_recovery(self.cases[case_id]["observation"])
            self.assertEqual(decision["process_action"], "none")
            self.assertIsNone(decision["append"]["evidence_event_type"])

    def test_only_idempotent_absent_effects_replay(self) -> None:
        safe = decide_recovery(self.cases["safe-replay-before-dispatch"]["observation"])
        unsafe = decide_recovery(self.cases["unsafe-replay-defer"]["observation"])
        self.assertTrue(safe["replay_step"])
        self.assertFalse(unsafe["replay_step"])


if __name__ == "__main__":
    unittest.main()
