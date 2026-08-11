from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_evaluation import run_evaluation, validate_result  # noqa: E402
from scripts.validate_dashboard_evaluation import validate as validate_lock  # noqa: E402


class DashboardRepeatedEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = validate_lock()
        cls.result = run_evaluation(cls.lock["lock_digest"])

    def test_exact_evaluation_lock_passes_without_runtime(self) -> None:
        self.assertEqual(self.lock["verification_verdict"], "PASS")
        self.assertEqual(self.lock["trials"], 27)
        self.assertFalse(self.lock["server_started"])

    def test_real_repeated_result_passes(self) -> None:
        result = validate_result(self.result, evaluation_lock_digest=self.lock["lock_digest"])
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertEqual(result["metrics"]["case_correctness"]["correct"], 27)
        self.assertEqual(result["metrics"]["request_failures"]["count"], 0)

    def test_claims_and_recovery_remain_calibrated(self) -> None:
        calibration = self.result["metrics"]["claim_calibration"]
        self.assertEqual(calibration["claims_permitted"], 3)
        self.assertEqual(calibration["claims_withheld"], 24)
        self.assertEqual(calibration["false_passes"], 0)
        self.assertTrue(self.result["recovery"]["all_recovered_without_claim_promotion"])

    def test_mutation_manifest_is_closed(self) -> None:
        manifest = json.loads((ROOT / "fixtures" / "dashboard" / "evaluation-mutations.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["mutations"]), 30)
        self.assertEqual(len({item["id"] for item in manifest["mutations"]}), 30)


if __name__ == "__main__":
    unittest.main()
