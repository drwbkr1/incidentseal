from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

from incidentseal.cli import UsageError, _parse  # noqa: E402
from incidentseal.integrated_recovery import STAGE_ORDER  # noqa: E402
from incidentseal.integrated_recovery_surface import (  # noqa: E402
    _case,
    _cross_cycle,
    _images,
    _safe_temporary,
    _tree_digest,
)
from incidentseal.topology import TopologyError  # noqa: E402


IMAGE_SET = [
    {"role": "database", "image_id": "sha256:" + "1" * 64},
    {"role": "migration", "image_id": "sha256:" + "2" * 64},
    {"role": "node-runner", "image_id": "sha256:" + "3" * 64},
    {"role": "python-runner", "image_id": "sha256:" + "4" * 64},
]
CONTRACT = "sha256:" + "5" * 64
ROOT_IDENTITY = {"incidentseal-protected": "sha256:" + "6" * 64}


def sample_cycle(repetition: int, archive_digit: str, receipt_digit: str) -> dict:
    stages = []
    for stage_id in STAGE_ORDER:
        semantic: dict = {}
        if stage_id == "receipt-state-matrix":
            semantic = {"receipt_digest": "sha256:" + "7" * 64, "bundle_digest": "sha256:" + "8" * 64}
        else:
            semantic = {"images": deepcopy(IMAGE_SET), "contract_digest": CONTRACT}
        if stage_id == "journal-probe":
            semantic["streams"] = {"stale": {"exit_code": 22, "stream_digest": "sha256:" + "9" * 64}}
        if stage_id == "recovery-probe":
            semantic["decisions"] = {"ambiguous": 11, "conflict": 21}
        if stage_id == "backup-restore-probe":
            semantic.update({
                "normalized_toc_digest": "sha256:" + "a" * 64,
                "restored_state": {"schema_digest": "sha256:" + "b" * 64},
                "negative_privileges": {"runner_ddl": "denied"},
                "raw_archive_receipt": {
                    "archive_digest": "sha256:" + archive_digit * 64,
                    "receipt_digest": "sha256:" + receipt_digit * 64,
                    "archive_bytes": 52800,
                },
            })
        stages.append({"id": stage_id, "semantic": semantic, "custody": {"unchanged": True}})
    return {
        "repetition": repetition,
        "stages": stages,
        "protected_volume_identity": deepcopy(ROOT_IDENTITY),
        "teardown_complete": True,
    }


class IntegratedRecoverySurfaceTests(unittest.TestCase):
    def test_composite_does_not_broaden_the_locked_cli(self) -> None:
        with self.assertRaises(UsageError):
            _parse(["topology", "integrated-recovery-probe", "--mode", "platform-validation", "--json"])

    def test_safe_temporary_rejects_repository_and_onedrive_named_custody(self) -> None:
        with self.assertRaises(TopologyError):
            _safe_temporary(ROOT)
        with tempfile.TemporaryDirectory(prefix="incidentseal-integrated-test-") as temporary:
            forbidden = Path(temporary) / "OneDrive" / "custody"
            forbidden.mkdir(parents=True)
            with self.assertRaises(TopologyError):
                _safe_temporary(forbidden)

    def test_case_requires_exact_lifecycle_verdict_and_exit(self) -> None:
        value = _case(
            "reliability-completed-fail",
            lifecycle="completed",
            run_verdict="FAIL",
            observation_verdict="FAIL",
            exit_code=10,
            evidence=["forced-verification-failure"],
        )
        self.assertEqual("completed", value["lifecycle"])
        self.assertEqual("FAIL", value["run_verdict"])
        with self.assertRaises(TopologyError):
            _case(
                "reliability-completed-fail",
                lifecycle="failed",
                run_verdict=None,
                observation_verdict="FAIL",
                exit_code=21,
                evidence=["collapsed"],
            )

    def test_tree_digest_is_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="incidentseal-integrated-tree-") as temporary:
            root = Path(temporary)
            (root / "a").mkdir()
            (root / "a" / "result.json").write_bytes(b'{"status":"PASS"}\n')
            first = _tree_digest(root)
            self.assertEqual(first, _tree_digest(root))
            (root / "a" / "result.json").write_bytes(b'{"status":"FAIL"}\n')
            self.assertNotEqual(first, _tree_digest(root))

    def test_image_projection_requires_all_exact_roles(self) -> None:
        source = {"images": [
            {"role": item["role"], "image_id": item["image_id"], "container_id": "excluded"}
            for item in reversed(IMAGE_SET)
        ]}
        self.assertEqual(IMAGE_SET, _images(source))
        source["images"].pop()
        with self.assertRaises(TopologyError):
            _images(source)

    def test_cross_cycle_allows_per_receipt_raw_archive_identity(self) -> None:
        result = _cross_cycle(
            [sample_cycle(1, "c", "d"), sample_cycle(2, "e", "f")],
            ROOT_IDENTITY,
        )
        self.assertTrue(result["same_normalized_toc"])
        self.assertNotEqual(
            result["raw_archive_receipts"][0]["archive_digest"],
            result["raw_archive_receipts"][1]["archive_digest"],
        )

    def test_cross_cycle_rejects_normalized_toc_drift(self) -> None:
        first = sample_cycle(1, "c", "d")
        second = sample_cycle(2, "e", "f")
        second["stages"][-1]["semantic"]["normalized_toc_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(TopologyError):
            _cross_cycle([first, second], ROOT_IDENTITY)

    def test_cross_cycle_rejects_teardown_or_protected_identity_drift(self) -> None:
        first = sample_cycle(1, "c", "d")
        second = sample_cycle(2, "e", "f")
        second["stages"][2]["custody"]["unchanged"] = False
        with self.assertRaises(TopologyError):
            _cross_cycle([first, second], ROOT_IDENTITY)
        second = sample_cycle(2, "e", "f")
        second["protected_volume_identity"] = {"incidentseal-protected": "sha256:" + "0" * 64}
        with self.assertRaises(TopologyError):
            _cross_cycle([first, second], ROOT_IDENTITY)


if __name__ == "__main__":
    unittest.main()
