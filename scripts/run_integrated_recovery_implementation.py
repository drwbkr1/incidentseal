#!/usr/bin/env python3
"""Run the fixed argument-free integrated recovery validation harness."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.cli import (  # noqa: E402
    EXIT_FAIL,
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_IO,
    EXIT_SUCCESS,
    EXIT_USAGE,
    _envelope,
    _error,
)
from incidentseal.integrated_recovery_surface import integrated_recovery_probe  # noqa: E402
from incidentseal.topology import TopologyError  # noqa: E402


COMMAND = "validation.integrated-recovery"


def execute(argv: Sequence[str]) -> tuple[dict, int]:
    arguments = list(argv)
    if arguments:
        envelope = _envelope(
            COMMAND,
            command_status="errored",
            process_exit_code=EXIT_USAGE,
            errors=[_error("IS_USAGE", "the integrated recovery validation harness accepts no arguments", None, False)],
        )
        return envelope, EXIT_USAGE
    try:
        data = integrated_recovery_probe()
        verdict = data["verdict"]
        exit_code = EXIT_SUCCESS if verdict == "PASS" else EXIT_FAIL
        envelope = _envelope(
            COMMAND,
            command_status="succeeded",
            process_exit_code=exit_code,
            verdict=verdict,
            data=data,
        )
        return envelope, exit_code
    except TopologyError as error:
        exit_code = EXIT_IO if error.io_error else EXIT_INVALID
        envelope = _envelope(
            COMMAND,
            command_status="errored" if error.io_error else "rejected",
            process_exit_code=exit_code,
            verdict=None if error.io_error else "INVALID",
            errors=[_error(error.code, str(error), None, error.io_error)],
        )
        return envelope, exit_code
    except Exception:
        envelope = _envelope(
            COMMAND,
            command_status="errored",
            process_exit_code=EXIT_INTERNAL,
            errors=[_error("IS_INTERNAL", "unexpected integrated recovery validation error", None, False)],
        )
        return envelope, EXIT_INTERNAL


def main(argv: Sequence[str] | None = None) -> int:
    envelope, exit_code = execute(sys.argv[1:] if argv is None else argv)
    encoded = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
