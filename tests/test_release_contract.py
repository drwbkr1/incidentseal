from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.release_contract import ReleaseContractError, validate_release_plan  # noqa: E402
from scripts.validate_release_contract import validate as validate_release_lock  # noqa: E402


PLAN = ROOT / "fixtures" / "release" / "release-plan.valid.json"


class ReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN.read_text(encoding="utf-8"))

    def test_golden_release_plan_is_content_addressed(self) -> None:
        result = validate_release_plan(self.plan)
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertTrue(result["plan_digest"].startswith("sha256:"))
        self.assertEqual(result["real_surfaces"], 13)

    def test_exact_release_contract_lock_passes(self) -> None:
        result = validate_release_lock()
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertEqual(result["locked_files"], 15)
        self.assertFalse(result["artifact_built"])
        self.assertFalse(result["docker_accessed"])
        self.assertFalse(result["published"])

    def test_approved_workflow_verification_precedes_packaging(self) -> None:
        result = validate_release_plan(self.plan)
        self.assertTrue(result["workflow_verification_required"])
        self.assertFalse(self.plan["workflow_verification"]["agent_can_approve"])
        self.assertEqual(self.plan["workflow_verification"]["docker_socket"], "denied")

    def test_package_has_no_runtime_dependency_or_pypi_channel(self) -> None:
        validate_release_plan(self.plan)
        self.assertEqual(self.plan["package"]["runtime_dependencies"], [])
        self.assertFalse(self.plan["package"]["pypi_publish"])

    def test_images_require_redistribution_and_digest_authority(self) -> None:
        validate_release_plan(self.plan)
        self.assertTrue(self.plan["supply_chain"]["redistribution_required_before_publish"])
        self.assertTrue(all(image["authority"] == "exact-registry-digest" for image in self.plan["images"]))

    def test_evidence_states_and_lifecycle_states_remain_distinct(self) -> None:
        validate_release_plan(self.plan)
        self.assertEqual(self.plan["evidence"]["verification_verdicts"], ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"])
        self.assertEqual(len(self.plan["evidence"]["lifecycle_states"]), 7)

    def test_immutable_publication_is_the_only_human_gate(self) -> None:
        result = validate_release_plan(self.plan)
        self.assertEqual(result["human_gates"], 1)
        self.assertTrue(self.plan["publication"]["immutable_release_required"])
        self.assertFalse(self.plan["publication"]["publish_before_all_gates"])

    def test_unknown_fields_fail_closed(self) -> None:
        candidate = deepcopy(self.plan)
        candidate["publication"]["latest_tag"] = True
        with self.assertRaises(ReleaseContractError) as context:
            validate_release_plan(candidate)
        self.assertEqual(context.exception.code, "IS_RELEASE_PUBLICATION")


if __name__ == "__main__":
    unittest.main()
