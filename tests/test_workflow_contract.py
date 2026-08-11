from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.workflow_contract import WorkflowContractError, validate_execution_contract  # noqa: E402
from scripts.validate_workflow_contract_lock import validate as validate_workflow_lock  # noqa: E402

CONTRACT = ROOT / "fixtures" / "workflow-verification" / "execution-contract.valid.json"


class WorkflowExecutionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_golden_contract_is_content_addressed(self) -> None:
        result = validate_execution_contract(self.contract)
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertTrue(result["contract_digest"].startswith("sha256:"))

    def test_exact_workflow_contract_lock_passes(self) -> None:
        result = validate_workflow_lock()
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertEqual(result["locked_files"], 14)
        self.assertFalse(result["workflow_executed"])
        self.assertFalse(result["docker_accessed"])

    def test_agent_cannot_approve_or_soften_missing_authority(self) -> None:
        validate_execution_contract(self.contract)
        self.assertFalse(self.contract["authority"]["agent_can_approve"])
        self.assertEqual(self.contract["authority"]["required_status"], "MATCH")
        self.assertEqual(self.contract["authority"]["non_match_verdict"], "INVALID")

    def test_only_python_and_node_are_supported(self) -> None:
        result = validate_execution_contract(self.contract)
        self.assertEqual(result["supported_runners"], 2)
        self.assertEqual(self.contract["runtime"]["supported_runners"], ["python", "node"])

    def test_runtime_trust_boundary_is_closed(self) -> None:
        validate_execution_contract(self.contract)
        runtime = self.contract["runtime"]
        self.assertEqual(runtime["docker_socket"], "denied")
        self.assertEqual(runtime["runtime_network"], "none")
        self.assertFalse(runtime["privileged"])
        self.assertFalse(runtime["host_environment_forwarded"])

    def test_persistent_outputs_are_not_supported(self) -> None:
        validate_execution_contract(self.contract)
        self.assertFalse(self.contract["staging"]["persistent_outputs_supported"])

    def test_verdict_and_lifecycle_are_independent(self) -> None:
        result = validate_execution_contract(self.contract)
        self.assertEqual(result["verification_verdicts"], 4)
        self.assertEqual(result["lifecycle_states"], 7)
        self.assertIsNone(self.contract["claim"]["non_completed_lifecycle_verdict"])

    def test_resume_never_crosses_manifest_digest(self) -> None:
        validate_execution_contract(self.contract)
        self.assertTrue(self.contract["recovery"]["different_digest_never_resumes"])
        self.assertTrue(self.contract["recovery"]["terminal_run_never_rewritten"])

    def test_unknown_fields_fail_closed(self) -> None:
        candidate = deepcopy(self.contract)
        candidate["runtime"]["network_alias"] = "host"
        with self.assertRaises(WorkflowContractError) as context:
            validate_execution_contract(candidate)
        self.assertEqual(context.exception.code, "IS_WORKFLOW_RUNTIME")


if __name__ == "__main__":
    unittest.main()
