"""Stable, dependency-free IncidentSeal machine CLI."""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Sequence

from .manifest import ALGORITHM, PROFILE, ManifestError, ManifestReadError, load_manifest


EXIT_SUCCESS = 0
EXIT_INVALID = 12
EXIT_USAGE = 64
EXIT_INTERNAL = 70
EXIT_IO = 74

COMMANDS = {
    ("policy", "lint"): "policy.lint",
    ("policy", "digest"): "policy.digest",
}


@dataclass(frozen=True)
class Request:
    command: str
    manifest: str


class UsageError(ValueError):
    """A request that cannot be interpreted as a stable command."""


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _error(code: str, message: str, detail: dict[str, Any] | None, retriable: bool) -> dict[str, Any]:
    return {
        "code": code,
        "message": message[:1000] or "IncidentSeal error",
        "detail": detail,
        "retriable": retriable,
    }


def _envelope(
    command: str,
    *,
    command_status: str,
    process_exit_code: int,
    verdict: str | None = None,
    policy: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "incidentseal-cli-envelope/v1",
        "command": command,
        "invocation_id": str(uuid.uuid4()),
        "emitted_at_utc": _timestamp(),
        "command_status": command_status,
        "process_exit_code": process_exit_code,
        "verdict": verdict,
        "lifecycle": None,
        "policy": policy,
        "data": data or {},
        "errors": errors or [],
        "evidence": [],
    }


def _parse(argv: Sequence[str]) -> Request:
    if len(argv) < 2 or tuple(argv[:2]) not in COMMANDS:
        raise UsageError("expected 'policy lint' or 'policy digest'")
    command = COMMANDS[tuple(argv[:2])]
    manifest: str | None = None
    json_requested = False
    index = 2
    while index < len(argv):
        token = argv[index]
        if token == "--json":
            if json_requested:
                raise UsageError("--json may be specified only once")
            json_requested = True
            index += 1
            continue
        if token == "--manifest":
            if manifest is not None or index + 1 >= len(argv):
                raise UsageError("--manifest requires exactly one path")
            manifest = argv[index + 1]
            index += 2
            continue
        raise UsageError(f"unknown argument: {token}")
    if not json_requested:
        raise UsageError("--json is required for the v1 machine CLI")
    if manifest is None or manifest == "":
        raise UsageError("--manifest requires exactly one path")
    return Request(command=command, manifest=manifest)


def _success(request: Request) -> dict[str, Any]:
    document = load_manifest(request.manifest)
    common = {
        "manifest_path": str(document.path),
        "schema_version": document.value["schema_version"],
        "workflow_id": document.value["workflow_id"],
        "revision": document.value["revision"],
    }
    if request.command == "policy.lint":
        return _envelope(
            request.command,
            command_status="succeeded",
            process_exit_code=EXIT_SUCCESS,
            data={**common, "valid": True},
        )
    return _envelope(
        request.command,
        command_status="succeeded",
        process_exit_code=EXIT_SUCCESS,
        data={
            **common,
            "algorithm": ALGORITHM,
            "profile": PROFILE,
            "canonical_byte_count": len(document.canonical),
            "manifest_digest": document.digest,
        },
    )


def execute(argv: Sequence[str]) -> tuple[dict[str, Any], int]:
    """Execute a machine request without writing process streams."""

    command = "cli.usage"
    try:
        request = _parse(argv)
        command = request.command
        envelope = _success(request)
        return envelope, envelope["process_exit_code"]
    except UsageError as error:
        envelope = _envelope(
            command,
            command_status="errored",
            process_exit_code=EXIT_USAGE,
            errors=[_error("IS_USAGE", str(error), None, False)],
        )
        return envelope, EXIT_USAGE
    except ManifestError as error:
        envelope = _envelope(
            command,
            command_status="rejected",
            process_exit_code=EXIT_INVALID,
            verdict="INVALID",
            errors=[_error(error.code, str(error), None, False)],
        )
        return envelope, EXIT_INVALID
    except ManifestReadError as error:
        envelope = _envelope(
            command,
            command_status="errored",
            process_exit_code=EXIT_IO,
            errors=[_error(error.code, str(error), None, True)],
        )
        return envelope, EXIT_IO
    except Exception:
        envelope = _envelope(
            command,
            command_status="errored",
            process_exit_code=EXIT_INTERNAL,
            errors=[_error("IS_INTERNAL", "unexpected internal CLI error", None, False)],
        )
        return envelope, EXIT_INTERNAL


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    envelope, exit_code = execute(arguments)
    encoded = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
    return exit_code
