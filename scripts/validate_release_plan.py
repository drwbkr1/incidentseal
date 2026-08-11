#!/usr/bin/env python3
"""Validate the runtime-free frozen IncidentSeal v0.1.0 release plan."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.release_contract import ReleaseContractError, validate_release_plan  # noqa: E402


PLAN = ROOT / "fixtures" / "release" / "release-plan.valid.json"


def validate() -> dict[str, object]:
    return validate_release_plan(strict_load_bytes(PLAN.read_bytes()))


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, ReleaseContractError) else "IS_RELEASE_INTERNAL"
        print(json.dumps({
            "schema_version": "incidentseal-release-plan-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
