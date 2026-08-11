from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_dashboard_browser import (  # noqa: E402
    EXPECTED_SCENARIOS,
    LOCK,
    jpeg_dimensions,
    load,
    validate,
)


class DashboardBrowserEvidenceTests(unittest.TestCase):
    def test_exact_browser_lock_passes(self) -> None:
        result = validate()
        self.assertEqual(result["verification_verdict"], "PASS")
        self.assertEqual(result["mobile_scenarios"], 9)
        self.assertEqual(result["screenshots"], 11)

    def test_each_retained_screenshot_is_jpeg(self) -> None:
        lock = load(LOCK)
        screenshots = [lock["desktop"]["screenshot"], lock["keyboard"]["screenshot"]]
        screenshots.extend(item["screenshot"] for item in lock["mobile_scenarios"])
        for item in screenshots:
            data = (ROOT / item["path"]).read_bytes()
            self.assertEqual(jpeg_dimensions(data), (item["width"], item["height"]))

    def test_scenario_order_is_frozen(self) -> None:
        lock = load(LOCK)
        observed = tuple((item["scenario_id"], item["kind"], item["label"], item["claim_allowed"]) for item in lock["mobile_scenarios"])
        self.assertEqual(observed, EXPECTED_SCENARIOS)

    def test_mutation_manifest_is_closed(self) -> None:
        manifest = json.loads((ROOT / "fixtures" / "dashboard" / "browser-mutations.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["mutations"]), 28)
        self.assertEqual(len({item["id"] for item in manifest["mutations"]}), 28)


if __name__ == "__main__":
    unittest.main()
