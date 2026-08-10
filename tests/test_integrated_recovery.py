from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.integrated_recovery import (  # noqa: E402
    IntegratedRecoveryError,
    matrix_digest,
    validate_matrix,
)


class IntegratedRecoveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads((ROOT / "fixtures" / "integrated-recovery" / "matrix.valid.json").read_text(encoding="utf-8"))

    def changed(self) -> dict:
        return deepcopy(self.golden)

    def test_golden_matrix_is_content_addressed(self) -> None:
        value = validate_matrix(self.changed())
        self.assertEqual(value["matrix_digest"], matrix_digest(value))
        self.assertEqual(len(value["cases"]), 20)

    def test_unknown_fields_fail_closed(self) -> None:
        value = self.changed()
        value["unexpected"] = True
        value["matrix_digest"] = matrix_digest(value)
        with self.assertRaises(IntegratedRecoveryError) as raised:
            validate_matrix(value)
        self.assertEqual(raised.exception.code, "IS_INTEGRATED_SCHEMA")

    def test_full_matrix_must_repeat(self) -> None:
        value = self.changed()
        value["composition"]["repetitions"] = 1
        value["matrix_digest"] = matrix_digest(value)
        with self.assertRaises(IntegratedRecoveryError) as raised:
            validate_matrix(value)
        self.assertEqual(raised.exception.code, "IS_INTEGRATED_REPEATABILITY")

    def test_lifecycle_failure_cannot_gain_verdict(self) -> None:
        value = self.changed()
        item = next(case for case in value["cases"] if case["id"] == "reliability-host-cancelled")
        item["expected_run_verdict"] = "FAIL"
        value["matrix_digest"] = matrix_digest(value)
        with self.assertRaises(IntegratedRecoveryError) as raised:
            validate_matrix(value)
        self.assertEqual(raised.exception.code, "IS_INTEGRATED_STATE")

    def test_ambiguous_recovery_cannot_be_promoted(self) -> None:
        value = self.changed()
        item = next(case for case in value["cases"] if case["id"] == "recovery-ambiguous-effects")
        item["expected_observation_verdict"] = "PASS"
        value["matrix_digest"] = matrix_digest(value)
        with self.assertRaises(IntegratedRecoveryError) as raised:
            validate_matrix(value)
        self.assertEqual(raised.exception.code, "IS_INTEGRATED_STATE")

    def test_raw_archive_is_bound_per_receipt_not_forced_equal(self) -> None:
        value = self.changed()
        value["cross_cycle"]["archive_identity_mode"] = "stable-raw-archive"
        value["matrix_digest"] = matrix_digest(value)
        with self.assertRaises(IntegratedRecoveryError) as raised:
            validate_matrix(value)
        self.assertEqual(raised.exception.code, "IS_INTEGRATED_REPEATABILITY")

    def test_protected_volume_and_teardown_gates_are_mandatory(self) -> None:
        for field in ("protected_volumes_unchanged", "teardown_between_stages", "teardown_after_cycle"):
            value = self.changed()
            value["cross_cycle"][field] = False
            value["matrix_digest"] = matrix_digest(value)
            with self.assertRaises(IntegratedRecoveryError) as raised:
                validate_matrix(value)
            self.assertEqual(raised.exception.code, "IS_INTEGRATED_CUSTODY")


if __name__ == "__main__":
    unittest.main()
