"""Static fail-closed validator for the fixed IncidentSeal dashboard implementation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


BUNDLE_PATHS = {
    "surface": "src/incidentseal/dashboard_surface.py",
    "css": "src/incidentseal/dashboard_assets/dashboard.css",
    "javascript": "src/incidentseal/dashboard_assets/dashboard.js",
    "windows_launcher": "incidentseal-dashboard.cmd",
    "posix_launcher": "incidentseal-dashboard",
}


class DashboardImplementationError(ValueError):
    """Stable dashboard implementation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise DashboardImplementationError(code, message)


def _require(text: str, fragments: tuple[str, ...], code: str, label: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        _reject(code, f"{label} contract differs: {missing[0]}")


def _forbid(text: str, fragments: tuple[str, ...], code: str, label: str) -> None:
    found = [fragment for fragment in fragments if fragment.lower() in text.lower()]
    if found:
        _reject(code, f"{label} gained forbidden capability: {found[0]}")


def source_bundle(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    root_resolved = root.resolve()
    for label, relative in BUNDLE_PATHS.items():
        path = (root_resolved / relative).resolve()
        if root_resolved not in path.parents or not path.is_file() or path.is_symlink():
            _reject("IS_DASHBOARD_IMPLEMENTATION_SOURCE", f"implementation file is unavailable: {relative}")
        result[label] = path.read_text(encoding="utf-8")
    return result


def validate_source_bundle(bundle: dict[str, str]) -> dict[str, Any]:
    if set(bundle) != set(BUNDLE_PATHS):
        _reject("IS_DASHBOARD_IMPLEMENTATION_SOURCE", "implementation bundle differs")
    surface = bundle["surface"]
    css = bundle["css"]
    javascript = bundle["javascript"]
    windows = bundle["windows_launcher"]
    posix = bundle["posix_launcher"]

    _require(surface, (
        'BIND_HOST = "127.0.0.1"',
        "address_family = socket.AF_INET\n",
        'return self.headers.get("Host") == f"{BIND_HOST}:{port}"',
        'target.query or target.path not in ROUTES',
        'ROUTES = ("/", "/assets/dashboard.css", "/assets/dashboard.js", "/api/snapshot", "/healthz")',
    ), "IS_DASHBOARD_IMPLEMENTATION_ROUTE", "loopback and fixed route")
    _require(surface, (
        'ALLOWED_METHODS = ("GET", "HEAD")',
        "def do_GET(self)", "def do_HEAD(self)",
        "do_POST = _write_denied", "do_PUT = _write_denied", "do_PATCH = _write_denied",
        "do_DELETE = _write_denied", "do_OPTIONS = _write_denied", "do_CONNECT = _write_denied",
        "do_TRACE = _write_denied",
    ), "IS_DASHBOARD_IMPLEMENTATION_METHOD", "read-only method")
    _require(surface, (
        '"Cache-Control": "no-store, max-age=0"',
        '"default-src \'none\'; style-src \'self\';',
        '"frame-ancestors \'none\'; object-src \'none\'"',
        '"Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"',
        '"Referrer-Policy": "no-referrer"',
        '"X-Content-Type-Options": "nosniff"',
        '"X-Frame-Options": "DENY"',
    ), "IS_DASHBOARD_IMPLEMENTATION_HEADER", "defensive header")
    _require(surface, (
        "snapshot = strict_load_bytes(_load_fixed(root_resolved, SNAPSHOT_PATH))",
        "validate_snapshot(snapshot, root_resolved)",
        "validate_corpus(corpus)",
        'return build_scenario_application(root, "dashboard-success")',
        'claim_text = "Claim permitted" if scenario["claim_allowed"] else "Claim withheld"',
        "snapshot_bytes = canonical_bytes(snapshot)",
        "path.is_symlink()",
        '"dashboard_creates_authority": False',
    ), "IS_DASHBOARD_IMPLEMENTATION_PROJECTION", "source-bound projection and scenario calibration")
    _forbid(surface, (
        "import subprocess", "from subprocess", "os.system", "socket.create_connection",
        "urllib.request", "requests.", ".write_text(", ".write_bytes(", ".unlink(",
        "approve_manifest", "operator approve", "docker.from_env", "docker compose",
    ), "IS_DASHBOARD_IMPLEMENTATION_AUTHORITY", "dashboard process")

    _require(css, (
        ":focus-visible", "@media (max-width: 620px)", "@media (prefers-reduced-motion: reduce)",
        "overflow-x: auto", "color: var(--invalid)",
    ), "IS_DASHBOARD_IMPLEMENTATION_PRESENTATION", "responsive and accessible style")
    _forbid(css, ("@import", "http://", "https://", "url("), "IS_DASHBOARD_IMPLEMENTATION_ASSET", "stylesheet")
    _require(javascript, ('"use strict";', 'document.documentElement.dataset.dashboard = "ready";'), "IS_DASHBOARD_IMPLEMENTATION_ASSET", "local script")
    _forbid(javascript, ("fetch(", "xmlhttprequest", "websocket", "eventsource", "http://", "https://", "localstorage", "sendbeacon"), "IS_DASHBOARD_IMPLEMENTATION_ASSET", "local script")

    _require(windows, (
        "setlocal", "INCIDENTSEAL_DASHBOARD_PYTHONPATH", "python -B -m incidentseal.dashboard_surface %*",
    ), "IS_DASHBOARD_IMPLEMENTATION_LAUNCHER", "Windows launcher")
    _require(posix, (
        "set -eu", "INCIDENTSEAL_DASHBOARD_ROOT", "INCIDENTSEAL_DASHBOARD_SOURCE",
        '-B -m incidentseal.dashboard_surface "$@"',
    ), "IS_DASHBOARD_IMPLEMENTATION_LAUNCHER", "POSIX launcher")
    _forbid(windows + posix, ("--root", "onedrive", "incidentseal.__main__", "incidentseal.cli"), "IS_DASHBOARD_IMPLEMENTATION_LAUNCHER", "launcher")
    return {
        "schema_version": "incidentseal-dashboard-source-validation/v1",
        "verification_verdict": "PASS",
        "fixed_routes": 5,
        "allowed_methods": 2,
        "denied_methods": 7,
        "local_assets": 2,
        "runtime_dependencies": 0,
    }


def validate_source_tree(root: Path) -> dict[str, Any]:
    return validate_source_bundle(source_bundle(root))
