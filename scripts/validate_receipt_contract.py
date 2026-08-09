#!/usr/bin/env python3
"""Dependency-free validation for the frozen IncidentSeal portable receipt contract."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from validate_machine_contracts import (
    ContractError as MachineContractError,
    _lint_schema_node,
    canonical_bytes,
    strict_load,
    validate_schema_instance,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures" / "receipts"
LOCK_PATH = ROOT / "requirements" / "receipt-contract.lock.json"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
GENESIS = "sha256:" + "0" * 64
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TERMINAL_LIFECYCLES = {"completed", "cancelled", "failed", "stale", "superseded"}
NULL_VERDICT_LIFECYCLES = {"queued", "running", "cancelled", "failed", "stale", "superseded"}
EVENT_TYPES = {
    "queued": {"run.queued"},
    "running": {
        "run.started",
        "policy.checked",
        "step.started",
        "step.completed",
        "step.failed",
        "evidence.recorded",
    },
    "completed": {"run.completed"},
    "cancelled": {"run.cancelled"},
    "failed": {"run.failed"},
    "stale": {"run.stale"},
    "superseded": {"run.superseded"},
}
LOCKED_PATHS = (
    "docs/decisions/ADR-0005-content-addressed-portable-receipts.md",
    "docs/receipt-contract.md",
    "docs/receipt-mutation-plan.md",
    "fixtures/receipts/artifacts/result.json",
    "fixtures/receipts/canonicalization-vectors.json",
    "fixtures/receipts/mutations.json",
    "fixtures/receipts/receipt.invalid.minimal.json",
    "fixtures/receipts/receipt.valid.json",
    "fixtures/receipts/verification.invalid.unbound-pass.json",
    "fixtures/receipts/verification.valid.json",
    "requirements/meta-validation.lock",
    "schemas/portable-receipt-v1.schema.json",
    "schemas/receipt-verification-v1.schema.json",
    "scripts/test_receipt_contract_mutations.py",
    "scripts/validate_json_schema_meta.py",
    "scripts/validate_machine_contracts.py",
    "scripts/validate_receipt_contract.py",
)


class ReceiptContractError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise ReceiptContractError(code, message)


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_contract_lock(root: Path = ROOT) -> dict[str, Any]:
    lock = strict_load(root / "requirements" / "receipt-contract.lock.json")
    if lock.get("schema_version") != "incidentseal-receipt-contract-lock/v1":
        reject("IS_RECEIPT_LOCK", "receipt contract lock schema version differs")
    if lock.get("contract_id") != "INCIDENTSEAL-RECEIPT-001" or lock.get("unit_id") != "IS4-U01":
        reject("IS_RECEIPT_LOCK", "receipt contract lock identity differs")
    entries = lock.get("files")
    if not isinstance(entries, list):
        reject("IS_RECEIPT_LOCK", "receipt contract lock files are invalid")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if len(paths) != len(entries) or len(paths) != len(set(paths)) or tuple(sorted(paths)) != LOCKED_PATHS:
        reject("IS_RECEIPT_LOCK", "receipt contract lock path set differs")
    for entry in entries:
        path = root / entry["path"]
        if not path.is_file() or sha256_bytes(path.read_bytes()) != entry.get("sha256"):
            reject("IS_RECEIPT_LOCK", f"receipt contract lock digest differs: {entry['path']}")
    if lock.get("canonicalization") != "RFC8785-JCS":
        reject("IS_RECEIPT_LOCK", "receipt canonicalization lock differs")
    return lock


def load_schema_documents(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    names = ("portable-receipt-v1.schema.json", "receipt-verification-v1.schema.json")
    return {name: strict_load(root / "schemas" / name) for name in names}


def validate_schema_documents(documents: dict[str, dict[str, Any]]) -> list[str]:
    checked: list[str] = []
    for name, document in documents.items():
        if document.get("$schema") != SCHEMA_DIALECT:
            reject("IS_RECEIPT_SCHEMA_DOCUMENT", f"{name} dialect is not Draft 2020-12")
        if not isinstance(document.get("$id"), str) or not document["$id"].startswith(
            "https://raw.githubusercontent.com/drwbkr1/incidentseal/main/schemas/"
        ):
            reject("IS_RECEIPT_SCHEMA_DOCUMENT", f"{name} has no stable repository-controlled $id")
        if document.get("type") != "object" or document.get("additionalProperties") is not False:
            reject("IS_RECEIPT_SCHEMA_DOCUMENT", f"{name} top-level object is not closed")
        try:
            _lint_schema_node(document, name, documents, "#")
        except MachineContractError as error:
            reject("IS_RECEIPT_SCHEMA_DOCUMENT", str(error))
        checked.append(name)
    if len(checked) != 2:
        reject("IS_RECEIPT_SCHEMA_DOCUMENT", "expected exactly two receipt schema documents")
    return checked


def schema_validate(
    value: Any,
    schema_name: str,
    documents: dict[str, dict[str, Any]],
) -> None:
    try:
        validate_schema_instance(documents[schema_name], value, schema_name, documents)
    except MachineContractError as error:
        reject("IS_RECEIPT_SCHEMA", str(error))


def expected_authority_digest(authority: dict[str, Any]) -> str:
    mode = authority["mode"]
    if mode == "approved-workflow":
        manifest = authority["manifest_digest"]
        approval = authority["approval_digest"]
        if (
            authority["workflow_id"] is None
            or manifest is None
            or approval is None
            or manifest != approval
            or authority["platform_contract_digest"] is not None
        ):
            reject("IS_RECEIPT_AUTHORITY", "approved-workflow authority fields are inconsistent")
        return manifest
    if (
        authority["workflow_id"] is not None
        or authority["manifest_digest"] is not None
        or authority["approval_digest"] is not None
        or authority["platform_contract_digest"] is None
    ):
        reject("IS_RECEIPT_AUTHORITY", "platform-validation authority fields are inconsistent")
    return authority["platform_contract_digest"]


def validate_event_state(event: dict[str, Any]) -> None:
    lifecycle = event["lifecycle"]
    terminal = event["terminal"]
    verdict = event["verdict"]
    if event["event_type"] not in EVENT_TYPES[lifecycle]:
        reject("IS_RECEIPT_STATE", "event type and lifecycle are inconsistent")
    if terminal != (lifecycle in TERMINAL_LIFECYCLES):
        reject("IS_RECEIPT_STATE", "event terminal flag and lifecycle are inconsistent")
    if lifecycle in NULL_VERDICT_LIFECYCLES and verdict is not None:
        reject("IS_RECEIPT_STATE", "lifecycle cannot carry a verification verdict")
    if lifecycle == "completed" and verdict is None:
        reject("IS_RECEIPT_STATE", "completed event requires an explicit verdict")


def validate_artifact_bytes(receipt: dict[str, Any], bundle_root: Path) -> None:
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    resolved_root = bundle_root.resolve(strict=True)
    for artifact in receipt["artifacts"]:
        artifact_id = artifact["artifact_id"]
        relative = artifact["path"]
        if artifact_id in seen_ids or relative.casefold() in seen_paths:
            reject("IS_RECEIPT_ARTIFACT", "artifact IDs and case-folded paths must be unique")
        seen_ids.add(artifact_id)
        seen_paths.add(relative.casefold())
        if not relative.startswith("artifacts/"):
            reject("IS_RECEIPT_ARTIFACT", "artifact path is outside the fixed artifact root")
        candidate = bundle_root / Path(*relative.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            if artifact["required"]:
                reject("IS_RECEIPT_ARTIFACT", f"required artifact is missing: {relative}")
            continue
        if resolved == resolved_root or resolved_root not in resolved.parents or candidate.is_symlink():
            reject("IS_RECEIPT_ARTIFACT", "artifact custody escapes or aliases the bundle root")
        raw = resolved.read_bytes()
        if len(raw) != artifact["byte_count"] or sha256_bytes(raw) != artifact["digest"]:
            reject("IS_RECEIPT_ARTIFACT", f"artifact bytes do not match descriptor: {relative}")


def validate_receipt(
    receipt: dict[str, Any],
    documents: dict[str, dict[str, Any]],
    *,
    bundle_root: Path = FIXTURES,
    verify_artifacts: bool = True,
) -> dict[str, Any]:
    schema_validate(receipt, "portable-receipt-v1.schema.json", documents)
    authority_digest = expected_authority_digest(receipt["authority"])

    seen_bindings: set[tuple[str, str]] = set()
    for binding in receipt["bindings"]:
        identity = (binding["kind"], binding["name"])
        if identity in seen_bindings:
            reject("IS_RECEIPT_BINDING", "binding kind and name pairs must be unique")
        seen_bindings.add(identity)

    chain = receipt["event_chain"]
    links = chain["links"]
    if chain["event_count"] != len(links):
        reject("IS_RECEIPT_EVENT_COUNT", "event_count does not equal retained link count")
    expected_previous = GENESIS
    run_id = receipt["run"]["run_id"]
    seen_event_ids: set[str] = set()
    terminal_indexes: list[int] = []
    for index, link in enumerate(links):
        if link["sequence"] != index or link["event"]["sequence"] != index:
            reject("IS_RECEIPT_SEQUENCE", "event sequences must be contiguous and zero-based")
        event = link["event"]
        if event["run_id"] != run_id:
            reject("IS_RECEIPT_STATE", "event run_id differs from the run summary")
        if event["event_id"] in seen_event_ids:
            reject("IS_RECEIPT_SEQUENCE", "event IDs must be unique")
        seen_event_ids.add(event["event_id"])
        if event["authority_digest"] != authority_digest:
            reject("IS_RECEIPT_AUTHORITY", "event authority digest differs from receipt authority")
        validate_event_state(event)
        if event["terminal"]:
            terminal_indexes.append(index)
        actual_event_digest = sha256_bytes(canonical_bytes(event))
        if link["event_digest"] != actual_event_digest:
            reject("IS_RECEIPT_EVENT_DIGEST", "event digest does not match canonical event bytes")
        if link["previous_link_digest"] != expected_previous:
            reject("IS_RECEIPT_LINK", "link predecessor does not match the prior link")
        link_preimage = {
            "schema_version": "incidentseal-event-link/v1",
            "sequence": index,
            "event_digest": actual_event_digest,
            "previous_link_digest": expected_previous,
        }
        actual_link_digest = sha256_bytes(canonical_bytes(link_preimage))
        if link["link_digest"] != actual_link_digest:
            reject("IS_RECEIPT_LINK", "link digest does not match its canonical preimage")
        expected_previous = actual_link_digest
    if chain["root_digest"] != expected_previous:
        reject("IS_RECEIPT_ROOT", "root digest does not equal the final link digest")

    summary = receipt["run"]
    final = links[-1]["event"]
    if summary["terminal"]:
        if terminal_indexes != [len(links) - 1]:
            reject("IS_RECEIPT_STATE", "a terminal run requires exactly one final terminal event")
        if summary["terminal_event_id"] != final["event_id"]:
            reject("IS_RECEIPT_STATE", "terminal event ID differs from the final event")
    elif terminal_indexes or summary["terminal_event_id"] is not None:
        reject("IS_RECEIPT_STATE", "non-terminal run cannot name or contain a terminal event")
    if (
        summary["lifecycle"] != final["lifecycle"]
        or summary["verdict"] != final["verdict"]
        or summary["terminal"] != final["terminal"]
    ):
        reject("IS_RECEIPT_STATE", "run summary differs from the final event state")
    if summary["lifecycle"] in NULL_VERDICT_LIFECYCLES and summary["verdict"] is not None:
        reject("IS_RECEIPT_STATE", "run lifecycle cannot carry a verification verdict")

    if verify_artifacts:
        validate_artifact_bytes(receipt, bundle_root)
    return {
        "receipt_digest": sha256_bytes(canonical_bytes(receipt)),
        "event_count": len(links),
        "root_digest": expected_previous,
        "artifact_count": len(receipt["artifacts"]),
    }


def validate_verification_report(
    report: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> None:
    schema_validate(report, "receipt-verification-v1.schema.json", documents)
    expected = report["expected_receipt_digest"]
    actual = report["receipt_digest"]
    identity = report["identity_status"]
    verdict = report["verification_verdict"]
    if expected is None:
        if identity != "UNBOUND" or verdict not in {"INCONCLUSIVE", "INVALID"}:
            reject("IS_RECEIPT_IDENTITY", "an unbound receipt cannot pass")
    elif actual is None:
        if identity != "INVALID" or verdict != "INVALID":
            reject("IS_RECEIPT_IDENTITY", "unreadable receipt identity must be invalid")
    elif actual == expected:
        if identity != "MATCH":
            reject("IS_RECEIPT_IDENTITY", "matching receipt digests require MATCH")
    elif identity != "MISMATCH" or verdict != "INVALID":
        reject("IS_RECEIPT_IDENTITY", "mismatched receipt digests must be INVALID")
    if verdict == "PASS" and not all(
        report[field] == "PASS"
        for field in ("schema_status", "semantic_status", "chain_status", "artifact_status")
    ):
        reject("IS_RECEIPT_IDENTITY", "PASS requires every verification dimension to pass")


def validate_contract(root: Path = ROOT) -> dict[str, Any]:
    lock = validate_contract_lock(root)
    documents = load_schema_documents(root)
    schemas = validate_schema_documents(documents)
    fixture_root = root / "fixtures" / "receipts"
    receipt = strict_load(fixture_root / "receipt.valid.json")
    result = validate_receipt(receipt, documents, bundle_root=fixture_root)
    vectors = strict_load(fixture_root / "canonicalization-vectors.json")
    if result["receipt_digest"] != vectors["receipt"]["digest"]:
        reject("IS_RECEIPT_CANONICAL", "receipt digest differs from the golden vector")
    if len(canonical_bytes(receipt)) != vectors["receipt"]["canonical_byte_count"]:
        reject("IS_RECEIPT_CANONICAL", "canonical receipt byte count differs")
    for actual, expected in zip(receipt["event_chain"]["links"], vectors["event_links"], strict=True):
        for field in ("sequence", "event_digest", "previous_link_digest", "link_digest"):
            if actual[field] != expected[field]:
                reject("IS_RECEIPT_CANONICAL", f"event-link vector differs at {field}")
    artifact_vector = vectors["artifact"]
    artifact = receipt["artifacts"][0]
    if (
        artifact["path"] != artifact_vector["path"]
        or artifact["byte_count"] != artifact_vector["byte_count"]
        or artifact["digest"] != artifact_vector["digest"]
    ):
        reject("IS_RECEIPT_CANONICAL", "artifact vector differs")

    verification = strict_load(fixture_root / "verification.valid.json")
    validate_verification_report(verification, documents)
    if verification["receipt_digest"] != result["receipt_digest"]:
        reject("IS_RECEIPT_IDENTITY", "golden verification does not bind the golden receipt")
    invalid_receipt = strict_load(fixture_root / "receipt.invalid.minimal.json")
    try:
        schema_validate(invalid_receipt, "portable-receipt-v1.schema.json", documents)
    except ReceiptContractError as error:
        if error.code != "IS_RECEIPT_SCHEMA":
            raise
    else:
        reject("IS_RECEIPT_SCHEMA", "invalid minimal receipt unexpectedly passed")
    invalid_verification = strict_load(fixture_root / "verification.invalid.unbound-pass.json")
    try:
        validate_verification_report(invalid_verification, documents)
    except ReceiptContractError as error:
        if error.code != "IS_RECEIPT_IDENTITY":
            raise
    else:
        reject("IS_RECEIPT_IDENTITY", "unbound PASS verification unexpectedly passed")

    return {
        "schema_version": "incidentseal-receipt-contract-validation/v1",
        "verdict": "PASS",
        "schemas": schemas,
        "receipt_digest": result["receipt_digest"],
        "event_count": result["event_count"],
        "artifact_count": result["artifact_count"],
        "root_digest": result["root_digest"],
        "lock_digest": sha256_bytes((root / "requirements" / "receipt-contract.lock.json").read_bytes()),
        "locked_files": len(lock["files"]),
        "canonicalization": "RFC8785-JCS",
        "independent_identity_required": True,
        "third_party_dependencies": 0,
        "runtime_started": False,
    }


def main() -> int:
    try:
        result = validate_contract(ROOT)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ReceiptContractError, MachineContractError, KeyError, OSError, TypeError, ValueError) as error:
        code = getattr(error, "code", "IS_RECEIPT_CONTRACT")
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-receipt-contract-validation/v1",
                    "verdict": "INVALID",
                    "error": {"code": code, "message": str(error)},
                    "runtime_started": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
