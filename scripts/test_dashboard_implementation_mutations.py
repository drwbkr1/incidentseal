#!/usr/bin/env python3
"""Require every bounded dashboard implementation mutation to fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.dashboard_implementation import (  # noqa: E402
    DashboardImplementationError,
    source_bundle,
    validate_source_bundle,
)


def replace(label: str, old: str, new: str) -> Callable[[dict[str, str]], None]:
    def mutate(bundle: dict[str, str]) -> None:
        if old not in bundle[label]:
            raise RuntimeError(f"mutation source differs: {label}: {old}")
        bundle[label] = bundle[label].replace(old, new, 1)
    return mutate


MUTATORS: dict[str, Callable[[dict[str, str]], None]] = {
    "non-loopback-bind": replace("surface", 'BIND_HOST = "127.0.0.1"', 'BIND_HOST = "0.0.0.0"'),
    "ipv6-server-enabled": replace("surface", "address_family = socket.AF_INET\n", "address_family = socket.AF_INET6\n"),
    "host-check-removed": replace("surface", 'return self.headers.get("Host") == f"{BIND_HOST}:{port}"', "return True"),
    "query-filter-removed": replace("surface", "target.query or target.path not in ROUTES", "target.path not in ROUTES"),
    "snapshot-route-removed": replace("surface", '"/api/snapshot"', '"/api/removed"'),
    "post-enabled": replace("surface", "do_POST = _write_denied", "do_POST = do_GET"),
    "delete-enabled": replace("surface", "do_DELETE = _write_denied", "do_DELETE = do_GET"),
    "trace-enabled": replace("surface", "do_TRACE = _write_denied", "do_TRACE = do_GET"),
    "cache-enabled": replace("surface", '"Cache-Control": "no-store, max-age=0"', '"Cache-Control": "public, max-age=3600"'),
    "csp-broadened": replace("surface", '"default-src \'none\'; style-src \'self\';', '"default-src *; style-src *;'),
    "framing-enabled": replace("surface", '"frame-ancestors \'none\'; object-src \'none\'"', '"frame-ancestors *; object-src *"'),
    "nosniff-removed": replace("surface", '"X-Content-Type-Options": "nosniff"', '"X-Content-Type-Options": ""'),
    "snapshot-validation-removed": replace("surface", "validate_snapshot(snapshot, root_resolved)", "snapshot.clear()"),
    "canonical-projection-removed": replace("surface", "snapshot_bytes = canonical_bytes(snapshot)", "snapshot_bytes = b'{}'"),
    "symlink-rejection-removed": replace("surface", " or path.is_symlink()", ""),
    "dashboard-authority-enabled": replace("surface", '"dashboard_creates_authority": False', '"dashboard_creates_authority": True'),
    "non-success-claim-enabled": replace("surface", 'claim_text = "Claim permitted" if scenario["claim_allowed"] else "Claim withheld"', 'claim_text = "Claim permitted"'),
    "subprocess-added": replace("surface", "import argparse", "import argparse\nimport subprocess"),
    "repository-write-added": replace("surface", "return path.read_bytes()", "path.write_text('changed')\n    return path.read_bytes()"),
    "external-client-added": replace("surface", "import socket", "import socket\nimport urllib.request"),
    "docker-client-added": replace("surface", "import socket", "import socket\nimport docker; docker.from_env()"),
    "mobile-layout-removed": replace("css", "@media (max-width: 620px)", "@media (min-width: 620px)"),
    "reduced-motion-removed": replace("css", "@media (prefers-reduced-motion: reduce)", "@media (prefers-reduced-motion: no-preference)"),
    "focus-style-removed": replace("css", ":focus-visible", ":hover"),
    "remote-css-added": replace("css", ":root {", "@import url(https://example.invalid/style.css);\n:root {"),
    "javascript-fetch-added": replace("javascript", '"use strict";', '"use strict";\nfetch("https://example.invalid/");'),
    "windows-launcher-target-changed": replace("windows_launcher", "incidentseal.dashboard_surface", "incidentseal.__main__"),
    "posix-launcher-target-changed": replace("posix_launcher", "incidentseal.dashboard_surface", "incidentseal.cli"),
    "launcher-root-override-added": replace("windows_launcher", "%*", "--root C:\\ %*"),
}


def main() -> int:
    golden = source_bundle(ROOT)
    manifest = json.loads((ROOT / "fixtures" / "dashboard" / "implementation-mutations.json").read_text(encoding="utf-8"))
    if tuple(MUTATORS) != tuple(item["id"] for item in manifest["mutations"]):
        raise RuntimeError("dashboard implementation mutation manifest differs")
    results = []
    for item in manifest["mutations"]:
        bundle = deepcopy(golden)
        MUTATORS[item["id"]](bundle)
        code = None
        try:
            validate_source_bundle(bundle)
        except DashboardImplementationError as error:
            code = error.code
        passed = code == item["expected_error"]
        results.append({
            "id": item["id"], "expected_error": item["expected_error"],
            "actual_error": code, "verification_verdict": "PASS" if passed else "FAIL",
        })
        if not passed:
            raise RuntimeError(f"mutation did not fail closed: {item['id']}: {code}")
    print(json.dumps({
        "schema_version": "incidentseal-dashboard-implementation-mutation-results/v1",
        "verification_verdict": "PASS", "mutation_count": len(results),
        "mutations": results, "runtime_started": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
