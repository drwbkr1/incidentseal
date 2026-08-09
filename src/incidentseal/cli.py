"""Stable, dependency-free IncidentSeal machine CLI."""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Sequence

from .approval import ApprovalResult, inspect_document
from .manifest import ALGORITHM, PROFILE, ManifestError, ManifestReadError, load_manifest
from .runtime import runtime_probe
from .topology import TopologyError, validate_platform_topology


EXIT_SUCCESS = 0
EXIT_INVALID = 12
EXIT_USAGE = 64
EXIT_INTERNAL = 70
EXIT_IO = 74
EXIT_FORBIDDEN = 77

COMMANDS = {
    ("policy", "lint"): "policy.lint",
    ("policy", "digest"): "policy.digest",
    ("policy", "status"): "policy.status",
    ("policy", "diff"): "policy.diff",
    ("topology", "validate"): "topology.validate",
    ("topology", "runtime-probe"): "topology.runtime-probe",
}


@dataclass(frozen=True)
class Request:
    command: str
    manifest: str | None
    mode: str | None


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
    evidence: list[dict[str, Any]] | None = None,
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
        "evidence": evidence or [],
    }


def _parse(argv: Sequence[str]) -> Request:
    if len(argv) < 2 or tuple(argv[:2]) not in COMMANDS:
        raise UsageError("expected a supported policy or topology command")
    command = COMMANDS[tuple(argv[:2])]
    manifest: str | None = None
    mode: str | None = None
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
        if token == "--mode":
            if mode is not None or index + 1 >= len(argv):
                raise UsageError("--mode requires exactly one value")
            mode = argv[index + 1]
            index += 2
            continue
        raise UsageError(f"unknown argument: {token}")
    if not json_requested:
        raise UsageError("--json is required for the v1 machine CLI")
    if command.startswith("policy."):
        if manifest is None or manifest == "":
            raise UsageError("--manifest requires exactly one path")
        if mode is not None:
            raise UsageError("--mode is not valid for policy commands")
    else:
        if manifest is not None:
            raise UsageError("--manifest is not valid for topology validation")
        if mode != "platform-validation":
            raise UsageError("--mode must be platform-validation")
    return Request(command=command, manifest=manifest, mode=mode)


def _approval_envelope(request: Request, document: Any, result: ApprovalResult) -> dict[str, Any]:
    policy = {
        "workflow_id": document.value["workflow_id"],
        "manifest_digest": document.digest,
        "approved_digest": result.approved_digest,
        "approval_status": result.status,
    }
    data: dict[str, Any] = {
        "approved": result.approved,
        "differences": list(result.differences),
    }
    if request.command == "policy.diff":
        data["comparison"] = "exact-bound-fields"
    if result.approved:
        return _envelope(
            request.command,
            command_status="succeeded",
            process_exit_code=EXIT_SUCCESS,
            policy=policy,
            data=data,
            evidence=result.evidence(),
        )
    error_code = result.error_code or "IS_APPROVAL_INVALID"
    message = result.message or "approval is invalid"
    return _envelope(
        request.command,
        command_status="rejected",
        process_exit_code=EXIT_INVALID,
        verdict="INVALID",
        policy=policy,
        data=data,
        errors=[_error(error_code, message, {"differences": list(result.differences)}, False)],
        evidence=result.evidence(),
    )


def _success(request: Request) -> dict[str, Any]:
    if request.command == "topology.validate":
        result = validate_platform_topology()
        return _envelope(
            request.command,
            command_status="succeeded",
            process_exit_code=EXIT_SUCCESS,
            verdict="PASS",
            data=result.data,
            evidence=result.evidence,
        )
    if request.command == "topology.runtime-probe":
        data = runtime_probe()
        return _envelope(
            request.command,
            command_status="succeeded",
            process_exit_code=EXIT_SUCCESS,
            verdict="PASS",
            data=data,
        )
    assert request.manifest is not None
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
    if request.command == "policy.digest":
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
    return _approval_envelope(request, document, inspect_document(document))


def execute(argv: Sequence[str]) -> tuple[dict[str, Any], int]:
    """Execute a machine request without writing process streams."""

    command = "cli.usage"
    try:
        if tuple(argv[:2]) == ("operator", "approve-manifest"):
            envelope = _envelope(
                "operator.approve-manifest",
                command_status="rejected",
                process_exit_code=EXIT_FORBIDDEN,
                verdict="INVALID",
                errors=[
                    _error(
                        "IS_AUTHORITY_MUTATION_FORBIDDEN",
                        "operator approval is unavailable through the agent-facing CLI",
                        None,
                        False,
                    )
                ],
            )
            return envelope, EXIT_FORBIDDEN
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
    except TopologyError as error:
        exit_code = EXIT_IO if error.io_error else EXIT_INVALID
        envelope = _envelope(
            command,
            command_status="errored" if error.io_error else "rejected",
            process_exit_code=exit_code,
            verdict=None if error.io_error else "INVALID",
            errors=[_error(error.code, str(error), None, False)],
        )
        return envelope, exit_code
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
    if tuple(arguments[:2]) == ("operator", "approve-manifest") and "--json" not in arguments:
        from .operator import main as operator_main

        return operator_main(arguments[2:])
    envelope, exit_code = execute(arguments)
    encoded = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
    return exit_code
