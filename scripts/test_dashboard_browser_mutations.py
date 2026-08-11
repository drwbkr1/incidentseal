#!/usr/bin/env python3
"""Require each browser-evidence mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_dashboard_browser import (  # noqa: E402
    BrowserEvidenceError,
    LOCK,
    load,
    validate_lock_data,
)


Mutator = Callable[[dict[str, Any]], None]


def set_path(*path: str, value: Any) -> Mutator:
    def mutate(lock: dict[str, Any]) -> None:
        current: Any = lock
        for part in path[:-1]:
            current = current[part]
        current[path[-1]] = value
    return mutate


def mobile(index: int, key: str, value: Any) -> Mutator:
    def mutate(lock: dict[str, Any]) -> None:
        lock["mobile_scenarios"][index][key] = value
    return mutate


def shrink_touch(lock: dict[str, Any]) -> None:
    lock["mobile_scenarios"][0]["visible_targets"][1]["height_css_px"] = "30.0"


def truncate_keyboard(lock: dict[str, Any]) -> None:
    lock["keyboard"]["focus_sequence"].pop()


def add_external_asset(lock: dict[str, Any]) -> None:
    lock["desktop"]["asset_paths"].append("https://example.invalid/style.css")


def change_screenshot_dimensions(lock: dict[str, Any]) -> None:
    lock["desktop"]["screenshot"]["width"] = 1400


def change_screenshot_digest(lock: dict[str, Any]) -> None:
    lock["desktop"]["screenshot"]["sha256"] = "sha256:" + "0" * 64


MUTATORS: dict[str, Mutator] = {
    "implementation-lock-changed": set_path("implementation_lock", "sha256", value="sha256:" + "0" * 64),
    "desktop-overflow": set_path("desktop", "document", "scroll_width", value=1426),
    "mobile-overflow": lambda lock: lock["mobile_scenarios"][0]["document"].__setitem__("scroll_width", 376),
    "success-claim-withheld": mobile(0, "claim_text", "Claim withheld"),
    "failure-claim-permitted": mobile(1, "claim_text", "Claim permitted"),
    "scenario-omitted": lambda lock: lock["mobile_scenarios"].pop(),
    "scenario-label-changed": mobile(2, "label", "Verified"),
    "touch-target-shrunk": shrink_touch,
    "contrast-weakened": lambda lock: lock["contrast"]["text_ratios"].__setitem__("panel_high", "3.9"),
    "keyboard-order-truncated": truncate_keyboard,
    "focus-indicator-removed": set_path("keyboard", "visible_focus_on_links", value=False),
    "keyboard-trap-added": set_path("keyboard", "no_trap", value=False),
    "main-duplicated": set_path("desktop", "landmarks", "main", value=2),
    "navigation-label-removed": set_path("desktop", "landmarks", "nav_label", value=None),
    "reduced-motion-removed": set_path("reduced_motion", "animation_removed", value=False),
    "external-asset-added": add_external_asset,
    "external-request-added": set_path("security_boundary", "external_requests", value=1),
    "browser-console-error-added": set_path("desktop", "console_error_or_warning_count", value=1),
    "screenshot-format-changed": set_path("desktop", "screenshot", "format", value="png"),
    "screenshot-dimensions-changed": change_screenshot_dimensions,
    "failure-retention-reduced": set_path("retained_attempts", "failures", "count", value=1),
    "invalid-retention-reduced": set_path("retained_attempts", "invalid", "count", value=12),
    "dashboard-approval-access-enabled": set_path("security_boundary", "approval_accessed", value=True),
    "workflow-execution-enabled": set_path("security_boundary", "workflow_executed", value=True),
    "docker-access-enabled": set_path("security_boundary", "docker_accessed", value=True),
    "scenario-http-selection-enabled": set_path("security_boundary", "scenario_http_selection", value=True),
    "favicon-denial-removed": set_path("observed_browser_assets", "favicon_probe_denied", value=False),
    "screenshot-digest-changed": change_screenshot_digest,
}


def main() -> int:
    golden = load(LOCK)
    manifest = load(ROOT / "fixtures" / "dashboard" / "browser-mutations.json")
    if tuple(MUTATORS) != tuple(item["id"] for item in manifest["mutations"]):
        raise RuntimeError("dashboard browser mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        candidate = deepcopy(golden)
        MUTATORS[item["id"]](candidate)
        code = None
        try:
            validate_lock_data(candidate, check_files=item["id"] == "screenshot-digest-changed")
        except BrowserEvidenceError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({
            "id":item["id"],"expected_error":item["expected_error"],
            "actual_error":code,"verification_verdict":"PASS" if passed else "FAIL",
        })
        if not passed:
            raise RuntimeError(f"browser mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({
        "schema_version":"incidentseal-dashboard-browser-mutation-results/v1",
        "verification_verdict":"PASS","mutation_count":len(results),
        "mutations":results,"server_started":False,"browser_started":False,"docker_started":False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
