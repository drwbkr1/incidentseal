#!/usr/bin/env python3
"""Validate retained U03 browser evidence without starting a browser or server."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402


LOCK = ROOT / "requirements" / "dashboard-browser.lock.json"
EXPECTED_SCENARIOS = (
    ("dashboard-success", "success", "Verified", True),
    ("dashboard-product-failure", "product-failure", "Product failure", False),
    ("dashboard-invalid-input", "invalid-input", "Invalid input", False),
    ("dashboard-missing-evidence", "missing-evidence", "Missing evidence", False),
    ("dashboard-policy-attack", "policy-attack", "Policy attack rejected", False),
    ("dashboard-isolation-attack", "isolation-attack", "Isolation attack rejected", False),
    ("dashboard-corrupt-receipt", "corrupt-receipt", "Corrupt receipt", False),
    ("dashboard-crash", "crash", "Dashboard interrupted", False),
    ("dashboard-recovery", "recovery", "Recovered evidence view", False),
)
EXPECTED_KEYBOARD = ("#main", "#top", "#checkpoint", "#states", "#provenance", "#limits", None)
EXPECTED_FILES = (
    "docs/dashboard-visual-acceptance.md",
    "fixtures/dashboard/browser-mutations.json",
    "records/browser-evidence/IS-0005-U03/desktop-dashboard-success.jpg",
    "records/browser-evidence/IS-0005-U03/desktop-keyboard-focus.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-corrupt-receipt.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-crash.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-invalid-input.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-isolation-attack.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-missing-evidence.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-policy-attack.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-product-failure.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-recovery.jpg",
    "records/browser-evidence/IS-0005-U03/mobile-dashboard-success.jpg",
    "records/evaluations/IS-0005-U03-rendered-browser-failures.json",
    "records/evaluations/IS-0005-U03-rendered-browser-invalid-attempts.json",
    "scripts/serve_dashboard_scenario.py",
    "scripts/test_dashboard_browser_mutations.py",
    "scripts/validate_dashboard_browser.py",
    "tests/test_dashboard_browser.py",
)


class BrowserEvidenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise BrowserEvidenceError(code, message)


def load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def jpeg_dimensions(data: bytes) -> tuple[int, int]:
    if not data.startswith(b"\xff\xd8"):
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "screenshot is not JPEG")
    position = 2
    sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while position + 9 <= len(data):
        if data[position] != 0xFF:
            position += 1
            continue
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            break
        marker = data[position]
        position += 1
        if marker in {0x01, 0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(data):
            break
        length = struct.unpack(">H", data[position:position + 2])[0]
        if length < 2 or position + length > len(data):
            break
        if marker in sof:
            height, width = struct.unpack(">HH", data[position + 3:position + 7])
            return width, height
        position += length
    reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "JPEG dimensions are unavailable")


def validate_screenshot(item: Any, check_files: bool) -> None:
    if not isinstance(item, dict) or item.get("format") != "jpeg":
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "screenshot format differs")
    if not isinstance(item.get("width"), int) or not isinstance(item.get("height"), int):
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "screenshot dimensions differ")
    if item["width"] <= 0 or item["height"] <= 0 or not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "screenshot size differs")
    if check_files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            reject("IS_DASHBOARD_BROWSER_FILE", f"screenshot drift: {item.get('path')}")
        data = path.read_bytes()
        if len(data) != item["bytes"]:
            reject("IS_DASHBOARD_BROWSER_FILE", f"screenshot byte count drift: {item.get('path')}")
        if jpeg_dimensions(data) != (item["width"], item["height"]):
            reject("IS_DASHBOARD_BROWSER_SCREENSHOT", f"screenshot dimensions drift: {item.get('path')}")


def local_asset_paths(value: Any) -> bool:
    return value == ["/assets/dashboard.css", "/assets/dashboard.js"]


def validate_lock_data(lock: Any, *, check_files: bool = True) -> dict[str, Any]:
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-dashboard-browser-lock/v1" or lock.get("revision") != 1:
        reject("IS_DASHBOARD_BROWSER_LOCK", "browser lock version differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_FILES:
        reject("IS_DASHBOARD_BROWSER_LOCK", "browser lock scope differs")
    if check_files:
        for item in files:
            path = ROOT / str(item.get("path", ""))
            if not path.is_file() or digest(path) != item.get("sha256"):
                reject("IS_DASHBOARD_BROWSER_FILE", f"browser evidence drift: {item.get('path')}")
    implementation = lock.get("implementation_lock")
    implementation_path = ROOT / "requirements" / "dashboard-implementation.lock.json"
    if implementation != {"path":"requirements/dashboard-implementation.lock.json","revision":3,"sha256":digest(implementation_path)}:
        reject("IS_DASHBOARD_BROWSER_IDENTITY", "dashboard implementation binding differs")

    desktop = lock.get("desktop")
    if not isinstance(desktop, dict) or desktop.get("scenario_id") != "dashboard-success" or desktop.get("viewport") != {"width":1440,"height":900}:
        reject("IS_DASHBOARD_BROWSER_LAYOUT", "desktop viewport differs")
    document = desktop.get("document") or {}
    if document.get("client_width") != 1425 or document.get("scroll_width") != 1425 or document.get("scroll_height") != 4859:
        reject("IS_DASHBOARD_BROWSER_LAYOUT", "desktop layout differs")
    if desktop.get("claim_allowed") is not True or desktop.get("claim_text") != "Claim permitted":
        reject("IS_DASHBOARD_BROWSER_CALIBRATION", "success claim calibration differs")
    landmarks = desktop.get("landmarks") or {}
    if landmarks != {"header":1,"nav":1,"nav_label":"Evidence sections","main":1,"footer":1}:
        reject("IS_DASHBOARD_BROWSER_ACCESSIBILITY", "desktop landmarks differ")
    semantics = desktop.get("semantics") or {}
    if semantics.get("main_id") != "main" or semantics.get("tables") != 1 or semantics.get("table_headers") != 3 or semantics.get("lists") != 5:
        reject("IS_DASHBOARD_BROWSER_ACCESSIBILITY", "desktop semantics differ")
    if not local_asset_paths(desktop.get("asset_paths")):
        reject("IS_DASHBOARD_BROWSER_ASSET", "desktop assets differ")
    if desktop.get("console_error_or_warning_count") != 0:
        reject("IS_DASHBOARD_BROWSER_BROWSER", "desktop browser log differs")
    desktop_screenshot = desktop.get("screenshot") or {}
    if (desktop_screenshot.get("width"), desktop_screenshot.get("height")) != (1425, 891):
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "desktop screenshot dimensions differ")
    validate_screenshot(desktop.get("screenshot"), check_files)

    mobile = lock.get("mobile_scenarios")
    if not isinstance(mobile, list) or len(mobile) != len(EXPECTED_SCENARIOS):
        reject("IS_DASHBOARD_BROWSER_SCENARIO", "mobile scenario count differs")
    for item, expected in zip(mobile, EXPECTED_SCENARIOS, strict=True):
        scenario_id, kind, label, claim_allowed = expected
        if not isinstance(item, dict) or (item.get("scenario_id"), item.get("kind"), item.get("label"), item.get("claim_allowed")) != expected:
            reject("IS_DASHBOARD_BROWSER_SCENARIO", f"scenario identity differs: {scenario_id}")
        expected_claim = "Claim permitted" if claim_allowed else "Claim withheld"
        if item.get("claim_text") != expected_claim:
            reject("IS_DASHBOARD_BROWSER_CALIBRATION", f"scenario claim differs: {scenario_id}")
        if item.get("viewport") != {"width":390,"height":844}:
            reject("IS_DASHBOARD_BROWSER_LAYOUT", f"mobile viewport differs: {scenario_id}")
        mobile_document = item.get("document") or {}
        if mobile_document.get("client_width") != 375 or mobile_document.get("scroll_width") != 375 or mobile_document.get("scroll_height", 0) < 7000:
            reject("IS_DASHBOARD_BROWSER_LAYOUT", f"mobile layout differs: {scenario_id}")
        if item.get("landmarks") != {"header":1,"nav":1,"main":1,"footer":1}:
            reject("IS_DASHBOARD_BROWSER_ACCESSIBILITY", f"mobile landmarks differ: {scenario_id}")
        targets = item.get("visible_targets")
        if not isinstance(targets, list) or len(targets) != 2 or min(float(target.get("height_css_px", "0")) for target in targets) < 44:
            reject("IS_DASHBOARD_BROWSER_TOUCH", f"mobile touch target differs: {scenario_id}")
        if not local_asset_paths(item.get("asset_paths")):
            reject("IS_DASHBOARD_BROWSER_ASSET", f"mobile assets differ: {scenario_id}")
        screenshot = item.get("screenshot") or {}
        if (screenshot.get("width"), screenshot.get("height")) != (375, 812):
            reject("IS_DASHBOARD_BROWSER_SCREENSHOT", f"mobile screenshot dimensions differ: {scenario_id}")
        validate_screenshot(item.get("screenshot"), check_files)

    keyboard = lock.get("keyboard")
    if not isinstance(keyboard, dict) or tuple(item.get("href") for item in keyboard.get("focus_sequence", []) if isinstance(item, dict)) != EXPECTED_KEYBOARD:
        reject("IS_DASHBOARD_BROWSER_KEYBOARD", "keyboard order differs")
    if keyboard.get("visible_focus_on_links") is not True or keyboard.get("no_trap") is not True or keyboard.get("outline_color") != "rgb(215, 255, 114)" or keyboard.get("outline_style") != "solid":
        reject("IS_DASHBOARD_BROWSER_KEYBOARD", "keyboard focus behavior differs")
    keyboard_screenshot = keyboard.get("screenshot") or {}
    if (keyboard_screenshot.get("width"), keyboard_screenshot.get("height")) != (1265, 569):
        reject("IS_DASHBOARD_BROWSER_SCREENSHOT", "keyboard screenshot dimensions differ")
    validate_screenshot(keyboard.get("screenshot"), check_files)

    contrast = lock.get("contrast") or {}
    ratios = contrast.get("text_ratios")
    if contrast.get("required_text_ratio") != "4.5" or not isinstance(ratios, dict) or min(float(value) for value in ratios.values()) < 4.5:
        reject("IS_DASHBOARD_BROWSER_CONTRAST", "text contrast differs")
    motion = lock.get("reduced_motion") or {}
    if motion.get("media_query") != "prefers-reduced-motion: reduce" or motion.get("animation_removed") is not True or motion.get("smooth_scroll_removed") is not True:
        reject("IS_DASHBOARD_BROWSER_ACCESSIBILITY", "reduced-motion behavior differs")

    assets = lock.get("observed_browser_assets") or {}
    urls = assets.get("urls")
    if not isinstance(urls, list) or len(urls) != 3 or any(urlsplit(str(url)).hostname != "127.0.0.1" for url in urls) or assets.get("favicon_probe_denied") is not True:
        reject("IS_DASHBOARD_BROWSER_ASSET", "observed browser assets differ")
    security = lock.get("security_boundary") or {}
    if security.get("bind_host") != "127.0.0.1" or security.get("external_requests") != 0 or security.get("repository_writes") != 0:
        reject("IS_DASHBOARD_BROWSER_SECURITY", "browser security boundary differs")
    if security.get("evaluation_only_scenario_processes") is not True or security.get("scenario_http_selection") is not False:
        reject("IS_DASHBOARD_BROWSER_AUTHORITY", "scenario selection authority differs")
    if security.get("approval_accessed") is not False or security.get("workflow_executed") is not False or security.get("docker_accessed") is not False:
        reject("IS_DASHBOARD_BROWSER_AUTHORITY", "browser authority boundary differs")

    retained = lock.get("retained_attempts") or {}
    if (retained.get("failures") or {}).get("count") != 2 or (retained.get("invalid") or {}).get("count") != 13:
        reject("IS_DASHBOARD_BROWSER_RETENTION", "retained attempt counts differ")
    mutations = load(ROOT / "fixtures" / "dashboard" / "browser-mutations.json")
    if not isinstance(mutations, dict) or len(mutations.get("mutations", [])) != 28:
        reject("IS_DASHBOARD_BROWSER_LOCK", "browser mutation count differs")
    if lock.get("runtime_dependencies") != [] or lock.get("browser_qa_requires_real_browser") is not True or lock.get("static_validator_rerenders_browser") is not False:
        reject("IS_DASHBOARD_BROWSER_LOCK", "browser validation boundary differs")
    return {"scenario_count":len(mobile),"screenshot_count":11,"mutation_count":28}


def validate() -> dict[str, Any]:
    lock = load(LOCK)
    observed = validate_lock_data(lock)
    return {
        "schema_version":"incidentseal-dashboard-browser-validation/v1",
        "verification_verdict":"PASS",
        "lock_digest":digest(LOCK),
        "implementation_lock_digest":digest(ROOT / "requirements" / "dashboard-implementation.lock.json"),
        "desktop_viewports":1,
        "mobile_scenarios":observed["scenario_count"],
        "screenshots":observed["screenshot_count"],
        "browser_mutations":observed["mutation_count"],
        "server_started":False,
        "browser_started":False,
        "docker_started":False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, BrowserEvidenceError) else "IS_DASHBOARD_BROWSER_INTERNAL"
        print(json.dumps({
            "schema_version":"incidentseal-dashboard-browser-validation/v1",
            "verification_verdict":"INVALID",
            "error":{"code":code,"message":str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
