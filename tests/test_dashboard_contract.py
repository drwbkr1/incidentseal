from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


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


class DashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = strict_load_bytes((ROOT / "fixtures" / "dashboard" / "snapshot.valid.json").read_bytes())
        cls.corpus = strict_load_bytes((ROOT / "fixtures" / "dashboard" / "scenario-corpus.valid.json").read_bytes())

    def test_golden_projection_is_exact_and_content_addressed(self) -> None:
        value = validate_snapshot(deepcopy(self.snapshot), ROOT)
        self.assertEqual(value["snapshot_digest"], snapshot_digest(value))
        self.assertEqual(len(value["source_records"]), 7)
        self.assertEqual(len(value["exits"]), 8)

    def test_golden_corpus_has_nine_repeated_scenarios(self) -> None:
        value = validate_corpus(deepcopy(self.corpus))
        self.assertEqual(value["corpus_digest"], corpus_digest(value))
        self.assertEqual(len(value["scenarios"]), 9)
        self.assertEqual(value["repetitions"], 3)

    def test_snapshot_rejects_source_record_drift(self) -> None:
        value = deepcopy(self.snapshot)
        value["source_records"][0]["sha256"] = "sha256:" + "9" * 64
        value["snapshot_digest"] = snapshot_digest(value)
        with self.assertRaises(DashboardContractError) as raised:
            validate_snapshot(value, ROOT)
        self.assertEqual(raised.exception.code, "IS_DASHBOARD_SOURCE")

    def test_non_loopback_and_write_methods_fail_closed(self) -> None:
        for field, replacement in (("bind_host", "0.0.0.0"), ("allowed_methods", ["GET", "HEAD", "POST"])):
            value = deepcopy(self.snapshot)
            value["trust_boundary"][field] = replacement
            value["snapshot_digest"] = snapshot_digest(value)
            with self.assertRaises(DashboardContractError) as raised:
                validate_snapshot(value, ROOT)
            self.assertEqual(raised.exception.code, "IS_DASHBOARD_CUSTODY")

    def test_dashboard_cannot_claim_approval_or_workflow(self) -> None:
        for field, replacement in (("approval_status", "MATCH"), ("workflow_executed", True), ("dashboard_creates_authority", True)):
            value = deepcopy(self.snapshot)
            value["authority"][field] = replacement
            value["snapshot_digest"] = snapshot_digest(value)
            with self.assertRaises(DashboardContractError) as raised:
                validate_snapshot(value, ROOT)
            self.assertEqual(raised.exception.code, "IS_DASHBOARD_AUTHORITY")

    def test_verdict_and_lifecycle_keys_cannot_collapse(self) -> None:
        for group, state in (("verification", "INVALID"), ("lifecycle", "cancelled"), ("lifecycle", "superseded")):
            value = deepcopy(self.snapshot)
            del value["states"][group][state]
            value["snapshot_digest"] = snapshot_digest(value)
            with self.assertRaises(DashboardContractError) as raised:
                validate_snapshot(value, ROOT)
            self.assertEqual(raised.exception.code, "IS_DASHBOARD_SCHEMA")

    def test_missing_evidence_cannot_be_promoted(self) -> None:
        value = deepcopy(self.corpus)
        item = next(case for case in value["scenarios"] if case["kind"] == "missing-evidence")
        item["claim_allowed"] = True
        value["corpus_digest"] = corpus_digest(value)
        with self.assertRaises(DashboardContractError) as raised:
            validate_corpus(value)
        self.assertEqual(raised.exception.code, "IS_DASHBOARD_SCENARIO")

    def test_policy_and_isolation_attacks_cannot_claim_success(self) -> None:
        for kind in ("policy-attack", "isolation-attack"):
            value = deepcopy(self.corpus)
            item = next(case for case in value["scenarios"] if case["kind"] == kind)
            item["claim_allowed"] = True
            value["corpus_digest"] = corpus_digest(value)
            with self.assertRaises(DashboardContractError) as raised:
                validate_corpus(value)
            self.assertEqual(raised.exception.code, "IS_DASHBOARD_SCENARIO")

    def test_crash_does_not_fabricate_verdict(self) -> None:
        value = deepcopy(self.corpus)
        item = next(case for case in value["scenarios"] if case["kind"] == "crash")
        item["run_verdict"] = "FAIL"
        value["corpus_digest"] = corpus_digest(value)
        with self.assertRaises(DashboardContractError) as raised:
            validate_corpus(value)
        self.assertEqual(raised.exception.code, "IS_DASHBOARD_SCENARIO")

    def test_evaluation_allows_no_false_claim_or_external_request(self) -> None:
        for field in ("external_requests", "write_requests", "false_pass_limit", "false_release_claim_limit"):
            value = deepcopy(self.corpus)
            value["evaluation"][field] = 1
            value["corpus_digest"] = corpus_digest(value)
            with self.assertRaises(DashboardContractError) as raised:
                validate_corpus(value)
            self.assertEqual(raised.exception.code, "IS_DASHBOARD_EVALUATION")


if __name__ == "__main__":
    unittest.main()
