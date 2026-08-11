#!/usr/bin/env python3
"""Validate the bounded approved-workflow execution contract."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.workflow_contract import WorkflowContractError, validate_execution_contract  # noqa: E402

CONTRACT = ROOT / "fixtures" / "workflow-verification" / "execution-contract.valid.json"


def main() -> int:
    try:
        result = validate_execution_contract(strict_load_bytes(CONTRACT.read_bytes()))
    except (OSError, ValueError, WorkflowContractError) as error:
        print(json.dumps({"schema_version":"incidentseal-workflow-execution-contract-validation/v1","verification_verdict":"INVALID","error_code":getattr(error, "code", "IS_WORKFLOW_IO"),"error":str(error)}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
