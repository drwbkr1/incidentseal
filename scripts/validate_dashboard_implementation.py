#!/usr/bin/env python3
"""Validate the exact locked dashboard implementation without starting a server."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.dashboard_implementation import (  # noqa: E402
    DashboardImplementationError,
    validate_source_tree,
)
from incidentseal.dashboard_surface import BIND_HOST, ROUTES, SECURITY_HEADERS, build_application  # noqa: E402
from incidentseal.manifest import strict_load_bytes  # noqa: E402


LOCK = ROOT / "requirements" / "dashboard-implementation.lock.json"
EXPECTED_PATHS = (
    "docs/dashboard-implementation.md",
    "fixtures/dashboard/implementation-mutations.json",
    "incidentseal-dashboard",
    "incidentseal-dashboard.cmd",
    "scripts/run_dashboard_implementation.py",
    "scripts/test_dashboard_implementation_mutations.py",
    "scripts/validate_dashboard_implementation.py",
    "src/incidentseal/dashboard_assets/dashboard.css",
    "src/incidentseal/dashboard_assets/dashboard.js",
    "src/incidentseal/dashboard_implementation.py",
    "src/incidentseal/dashboard_surface.py",
    "tests/test_dashboard_surface.py",
)
FROZEN_CLI_PATHS = (
    "incidentseal",
    "incidentseal.cmd",
    "src/incidentseal/__main__.py",
    "src/incidentseal/cli.py",
)


def load(path: Path) -> Any:
    return strict_load_bytes(path.read_bytes())


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_lock() -> tuple[str, dict[str, Any]]:
    lock = load(LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-dashboard-implementation-lock/v1":
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "dashboard implementation lock version differs")
    files = lock.get("files")
    if not isinstance(files, list) or tuple(item.get("path") for item in files if isinstance(item, dict)) != EXPECTED_PATHS:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "dashboard implementation lock scope differs")
    for item in files:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", f"dashboard implementation drift: {item.get('path')}")
    frozen = lock.get("frozen_verification_cli")
    if not isinstance(frozen, list) or tuple(item.get("path") for item in frozen if isinstance(item, dict)) != FROZEN_CLI_PATHS:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "frozen verification CLI scope differs")
    for item in frozen:
        path = ROOT / str(item.get("path", ""))
        if not path.is_file() or digest(path) != item.get("sha256"):
            raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", f"frozen verification CLI drift: {item.get('path')}")
    contract = ROOT / "requirements" / "dashboard-contract.lock.json"
    if lock.get("contract_lock") != {"path": "requirements/dashboard-contract.lock.json", "sha256": digest(contract)}:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "dashboard contract binding differs")
    if lock.get("runtime_dependencies") != [] or lock.get("separate_launcher") is not True or lock.get("verification_cli_changed") is not False:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "dashboard implementation boundary differs")
    if stat.S_IMODE((ROOT / "incidentseal-dashboard").stat().st_mode) & stat.S_IXUSR == 0 and sys.platform != "win32":
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LAUNCHER", "POSIX launcher is not executable")
    return digest(LOCK), lock


def validate() -> dict[str, Any]:
    lock_digest, lock = validate_lock()
    source = validate_source_tree(ROOT)
    application = build_application(ROOT)
    expected = lock.get("golden", {})
    observed = {
        "snapshot_digest": application.snapshot["snapshot_digest"],
        "html_digest": "sha256:" + hashlib.sha256(application.html_bytes).hexdigest(),
        "css_digest": "sha256:" + hashlib.sha256(application.css_bytes).hexdigest(),
        "javascript_digest": "sha256:" + hashlib.sha256(application.javascript_bytes).hexdigest(),
        "health_digest": "sha256:" + hashlib.sha256(application.health_bytes).hexdigest(),
        "routes": len(ROUTES),
        "security_headers": len(SECURITY_HEADERS),
        "bind_host": BIND_HOST,
    }
    if expected != observed:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_IDENTITY", "dashboard golden projection differs")
    mutations = load(ROOT / "fixtures" / "dashboard" / "implementation-mutations.json")
    mutation_count = len(mutations.get("mutations", [])) if isinstance(mutations, dict) else 0
    if mutation_count != 29:
        raise DashboardImplementationError("IS_DASHBOARD_IMPLEMENTATION_LOCK", "dashboard implementation mutation count differs")
    return {
        "schema_version": "incidentseal-dashboard-implementation-validation/v1",
        "verification_verdict": "PASS",
        "lock_digest": lock_digest,
        "snapshot_digest": observed["snapshot_digest"],
        "html_digest": observed["html_digest"],
        "fixed_routes": source["fixed_routes"],
        "allowed_methods": source["allowed_methods"],
        "denied_methods": source["denied_methods"],
        "security_headers": observed["security_headers"],
        "implementation_mutations": mutation_count,
        "runtime_dependencies": 0,
        "server_started": False,
        "browser_started": False,
        "docker_started": False,
        "verification_cli_changed": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, DashboardImplementationError) else "IS_DASHBOARD_IMPLEMENTATION_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-implementation-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
