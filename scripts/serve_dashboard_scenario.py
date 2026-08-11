#!/usr/bin/env python3
"""Serve one exact frozen dashboard scenario for real-browser evaluation only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_contract import EXPECTED_SCENARIOS  # noqa: E402
from incidentseal.dashboard_surface import BIND_HOST, DashboardServer, build_scenario_application  # noqa: E402
from scripts.validate_dashboard_implementation import validate as validate_implementation  # noqa: E402


SCENARIO_IDS = tuple(item[0] for item in EXPECTED_SCENARIOS)


def main() -> int:
    parser = argparse.ArgumentParser(prog="serve-dashboard-scenario")
    parser.add_argument("--scenario-id", required=True, choices=SCENARIO_IDS)
    parser.add_argument("--port", type=int, default=0, choices=range(0, 65536))
    args = parser.parse_args()
    if args.port != 0 and not 1024 <= args.port <= 65535:
        parser.error("port must be 0 or between 1024 and 65535")
    validation = validate_implementation()
    application = build_scenario_application(ROOT, args.scenario_id)
    with DashboardServer(args.port, application) as server:
        startup = {
            "schema_version": "incidentseal-dashboard-browser-fixture/v1",
            "status": "ready",
            "evaluation_only": True,
            "scenario_id": args.scenario_id,
            "bind_host": BIND_HOST,
            "port": int(server.server_address[1]),
            "implementation_lock_digest": validation["lock_digest"],
            "snapshot_digest": application.snapshot["snapshot_digest"],
        }
        print(json.dumps(startup, sort_keys=True, separators=(",", ":")), flush=True)
        try:
            server.serve_forever(poll_interval=0.1)
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
