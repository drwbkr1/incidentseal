"""Atomic portable receipt materialization and read-only offline verification."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any

from .manifest import ManifestError, canonical_bytes, strict_load_bytes


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
GENESIS = "sha256:" + "0" * 64
PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATION_LOCK = PROJECT_ROOT / "requirements" / "receipt-implementation.lock.json"
LIFECYCLES = {"queued", "running", "completed", "cancelled", "failed", "stale", "superseded"}
VERDICTS = {"PASS", "FAIL", "INCONCLUSIVE", "INVALID"}
TERMINAL = {"completed", "cancelled", "failed", "stale", "superseded"}
EVENT_TYPES = {
    "queued": {"run.queued"},
    "running": {"run.started", "policy.checked", "step.started", "step.completed", "step.failed", "evidence.recorded"},
    "completed": {"run.completed"},
    "cancelled": {"run.cancelled"},
    "failed": {"run.failed"},
    "stale": {"run.stale"},
    "superseded": {"run.superseded"},
}


class ReceiptError(ValueError):
    def __init__(self, code: str, message: str, *, io_error: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.io_error = io_error


def _reject(code: str, message: str, *, io_error: bool = False) -> None:
    raise ReceiptError(code, message, io_error=io_error)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _exact(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        _reject("IS_RECEIPT_SCHEMA", f"{label} fields differ from v1")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _reject("IS_RECEIPT_SCHEMA", f"{label} is not a lowercase SHA-256 digest")
    return value


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        _reject("IS_RECEIPT_SCHEMA", f"{label} is not a lowercase UUIDv4")
    return value


def _safe_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1000
        or SAFE_PATH_RE.fullmatch(value) is None
        or ".." in value.split("/")
        or "\\" in value
    ):
        _reject("IS_RECEIPT_CUSTODY", "artifact path is not a safe relative POSIX path")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReceiptError("IS_RECEIPT_READ", f"could not read receipt: {path}", io_error=True) from error
    try:
        value = strict_load_bytes(raw)
    except ManifestError as error:
        raise ReceiptError("IS_RECEIPT_JSON", str(error)) from error
    if not isinstance(value, dict):
        _reject("IS_RECEIPT_SCHEMA", "receipt root is not an object")
    return value


def _validate_implementation_lock() -> None:
    try:
        lock = strict_load_bytes(IMPLEMENTATION_LOCK.read_bytes())
    except OSError as error:
        raise ReceiptError("IS_RECEIPT_IMPLEMENTATION", "receipt implementation lock is unavailable") from error
    except ManifestError as error:
        raise ReceiptError("IS_RECEIPT_IMPLEMENTATION", "receipt implementation lock is invalid") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-receipt-implementation-lock/v1":
        _reject("IS_RECEIPT_IMPLEMENTATION", "receipt implementation lock version differs")
    entries = lock.get("files")
    runtime_files = lock.get("runtime_files")
    if not isinstance(entries, list) or not isinstance(runtime_files, list) or not runtime_files:
        _reject("IS_RECEIPT_IMPLEMENTATION", "receipt implementation lock file sets are invalid")
    mapped = {
        entry.get("path"): entry.get("sha256")
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    if len(mapped) != len(entries) or len(runtime_files) != len(set(runtime_files)):
        _reject("IS_RECEIPT_IMPLEMENTATION", "receipt implementation lock contains duplicate paths")
    for relative in runtime_files:
        if relative not in mapped:
            _reject("IS_RECEIPT_IMPLEMENTATION", f"runtime file is absent from implementation lock: {relative}")
        path = PROJECT_ROOT / relative
        try:
            actual = _digest(path.read_bytes())
        except OSError as error:
            raise ReceiptError("IS_RECEIPT_IMPLEMENTATION", f"runtime file is unavailable: {relative}") from error
        if actual != mapped[relative]:
            _reject("IS_RECEIPT_IMPLEMENTATION", f"runtime file digest differs: {relative}")


def _is_reparse(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return path.is_symlink() or bool(
        getattr(details, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _reparse_component(path: Path) -> Path | None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and _is_reparse(current):
            return current
    return None


def _forbidden_custody(path: Path) -> str | None:
    normalized = str(path).replace("/", "\\").casefold()
    if "\\onedrive\\" in normalized or normalized.endswith("\\onedrive"):
        return "OneDrive custody is forbidden"
    resolved_project = PROJECT_ROOT.resolve(strict=True)
    try:
        resolved_path = path.resolve(strict=False)
    except OSError:
        resolved_path = path.absolute()
    if resolved_path == resolved_project or resolved_project in resolved_path.parents:
        return "runtime receipt output cannot be inside repository custody"
    return None


def _authority(receipt: dict[str, Any]) -> str:
    authority = _exact(
        receipt["authority"],
        {"mode", "workflow_id", "manifest_digest", "approval_digest", "platform_contract_digest"},
        "authority",
    )
    if authority["mode"] == "approved-workflow":
        manifest = _sha(authority["manifest_digest"], "manifest digest")
        approval = _sha(authority["approval_digest"], "approval digest")
        if not isinstance(authority["workflow_id"], str) or manifest != approval or authority["platform_contract_digest"] is not None:
            _reject("IS_RECEIPT_AUTHORITY", "approved-workflow authority is inconsistent")
        return manifest
    if authority["mode"] == "platform-validation":
        if any(authority[name] is not None for name in ("workflow_id", "manifest_digest", "approval_digest")):
            _reject("IS_RECEIPT_AUTHORITY", "platform validation cannot carry workflow approval")
        return _sha(authority["platform_contract_digest"], "platform contract digest")
    _reject("IS_RECEIPT_AUTHORITY", "unknown receipt authority mode")


def _validate_structure(receipt: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    _exact(
        receipt,
        {"schema_version", "receipt_id", "created_at_utc", "authority", "source", "bindings", "run", "event_chain", "artifacts", "custody"},
        "receipt",
    )
    if receipt["schema_version"] != "incidentseal-portable-receipt/v1":
        _reject("IS_RECEIPT_SCHEMA", "receipt schema version differs")
    _uuid(receipt["receipt_id"], "receipt_id")
    authority_digest = _authority(receipt)
    source = _exact(receipt["source"], {"repository", "commit", "tree"}, "source")
    if not isinstance(source["repository"], str) or not source["repository"].startswith("https://"):
        _reject("IS_RECEIPT_SCHEMA", "source repository is invalid")
    if not all(isinstance(source[name], str) and len(source[name]) in {40, 64} and re.fullmatch(r"[0-9a-f]+", source[name]) for name in ("commit", "tree")):
        _reject("IS_RECEIPT_SCHEMA", "source Git identity is invalid")
    bindings = receipt["bindings"]
    if not isinstance(bindings, list) or not bindings:
        _reject("IS_RECEIPT_SCHEMA", "receipt requires bindings")
    seen_bindings: set[tuple[str, str]] = set()
    for binding_value in bindings:
        binding = _exact(binding_value, {"kind", "name", "digest"}, "binding")
        identity = (binding["kind"], binding["name"])
        if not all(isinstance(item, str) and item for item in identity) or identity in seen_bindings:
            _reject("IS_RECEIPT_BINDING", "binding identity is invalid or duplicated")
        seen_bindings.add(identity)
        _sha(binding["digest"], "binding digest")

    summary = _exact(receipt["run"], {"run_id", "lifecycle", "verdict", "terminal", "terminal_event_id"}, "run")
    run_id = _uuid(summary["run_id"], "run_id")
    if summary["lifecycle"] not in LIFECYCLES or summary["verdict"] not in VERDICTS | {None} or not isinstance(summary["terminal"], bool):
        _reject("IS_RECEIPT_STATE", "run summary state is invalid")
    if summary["terminal_event_id"] is not None:
        _uuid(summary["terminal_event_id"], "terminal_event_id")

    chain = _exact(receipt["event_chain"], {"algorithm", "canonicalization", "genesis_digest", "event_count", "root_digest", "links"}, "event_chain")
    if chain["algorithm"] != "sha256-rfc8785-link-v1" or chain["canonicalization"] != "RFC8785-JCS" or chain["genesis_digest"] != GENESIS:
        _reject("IS_RECEIPT_SCHEMA", "event chain algorithm differs")
    links = chain["links"]
    if not isinstance(links, list) or not links or chain["event_count"] != len(links):
        _reject("IS_RECEIPT_EVENT_COUNT", "event count differs from retained links")
    previous = GENESIS
    terminal_indexes: list[int] = []
    event_ids: set[str] = set()
    for index, link_value in enumerate(links):
        link = _exact(link_value, {"sequence", "event_digest", "previous_link_digest", "link_digest", "event"}, "event link")
        event = _exact(
            link["event"],
            {"schema_version", "event_id", "run_id", "sequence", "occurred_at_utc", "event_type", "lifecycle", "verdict", "terminal", "authority_digest", "payload", "error"},
            "event",
        )
        if link["sequence"] != index or event["sequence"] != index:
            _reject("IS_RECEIPT_SEQUENCE", "event sequence is not contiguous")
        event_id = _uuid(event["event_id"], "event_id")
        if event_id in event_ids or event["run_id"] != run_id:
            _reject("IS_RECEIPT_SEQUENCE", "event identity is duplicated or cross-run")
        event_ids.add(event_id)
        if event["schema_version"] != "incidentseal-evidence-event/v1" or event["authority_digest"] != authority_digest:
            _reject("IS_RECEIPT_AUTHORITY", "event authority differs")
        lifecycle = event["lifecycle"]
        if lifecycle not in LIFECYCLES or event["event_type"] not in EVENT_TYPES[lifecycle] or not isinstance(event["terminal"], bool):
            _reject("IS_RECEIPT_STATE", "event state is invalid")
        if event["terminal"] != (lifecycle in TERMINAL):
            _reject("IS_RECEIPT_STATE", "event terminal state differs")
        if lifecycle == "completed":
            if event["verdict"] not in VERDICTS:
                _reject("IS_RECEIPT_STATE", "completed event requires a verdict")
        elif event["verdict"] is not None:
            _reject("IS_RECEIPT_STATE", "non-completed lifecycle cannot carry a verdict")
        if event["terminal"]:
            terminal_indexes.append(index)
        event_digest = _digest(canonical_bytes(event))
        if link["event_digest"] != event_digest:
            _reject("IS_RECEIPT_EVENT_DIGEST", "event digest differs")
        if link["previous_link_digest"] != previous:
            _reject("IS_RECEIPT_LINK", "link predecessor differs")
        preimage = {"schema_version": "incidentseal-event-link/v1", "sequence": index, "event_digest": event_digest, "previous_link_digest": previous}
        link_digest = _digest(canonical_bytes(preimage))
        if link["link_digest"] != link_digest:
            _reject("IS_RECEIPT_LINK", "link digest differs")
        previous = link_digest
    if chain["root_digest"] != previous:
        _reject("IS_RECEIPT_ROOT", "event root differs")
    final = links[-1]["event"]
    if summary["terminal"]:
        if terminal_indexes != [len(links) - 1] or summary["terminal_event_id"] != final["event_id"]:
            _reject("IS_RECEIPT_STATE", "terminal event binding differs")
    elif terminal_indexes or summary["terminal_event_id"] is not None:
        _reject("IS_RECEIPT_STATE", "non-terminal run contains a terminal event")
    if any(summary[name] != final[name] for name in ("lifecycle", "verdict", "terminal")):
        _reject("IS_RECEIPT_STATE", "run summary differs from final event")

    custody = _exact(receipt["custody"], {"layout", "artifact_root", "path_policy", "network_required", "docker_required", "database_required", "secret_required"}, "custody")
    expected_custody = {"layout": "incidentseal-portable-bundle/v1", "artifact_root": "artifacts", "path_policy": "safe-relative-posix", "network_required": False, "docker_required": False, "database_required": False, "secret_required": False}
    if custody != expected_custody:
        _reject("IS_RECEIPT_CUSTODY", "receipt custody boundary differs")
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list):
        _reject("IS_RECEIPT_SCHEMA", "artifacts must be an array")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for artifact_value in artifacts:
        artifact = _exact(artifact_value, {"artifact_id", "kind", "path", "media_type", "byte_count", "digest", "required"}, "artifact")
        path = _safe_path(artifact["path"])
        if not path.startswith("artifacts/") or not isinstance(artifact["artifact_id"], str) or artifact["artifact_id"] in seen_ids or path.casefold() in seen_paths:
            _reject("IS_RECEIPT_CUSTODY", "artifact identity or root is invalid")
        seen_ids.add(artifact["artifact_id"])
        seen_paths.add(path.casefold())
        if not isinstance(artifact["byte_count"], int) or isinstance(artifact["byte_count"], bool) or artifact["byte_count"] < 0 or not isinstance(artifact["required"], bool):
            _reject("IS_RECEIPT_SCHEMA", "artifact size or required flag is invalid")
        _sha(artifact["digest"], "artifact digest")
    return authority_digest, artifacts


def _artifact_state(receipt: dict[str, Any], artifacts: list[dict[str, Any]], bundle_root: Path) -> tuple[str, list[dict[str, Any]]]:
    reparse = _reparse_component(bundle_root.absolute())
    if reparse is not None:
        _reject("IS_RECEIPT_CUSTODY", f"bundle custody contains a reparse point: {reparse}")
    root = bundle_root.resolve(strict=True)
    errors: list[dict[str, Any]] = []
    status = "PASS"
    for artifact in artifacts:
        relative = artifact["path"]
        candidate = bundle_root / Path(*relative.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            if artifact["required"]:
                status = "INCONCLUSIVE"
                errors.append({"code": "IS_RECEIPT_ARTIFACT_MISSING", "message": f"required artifact missing: {relative}", "retriable": True})
            continue
        if root not in resolved.parents or _reparse_component(candidate.absolute()) is not None:
            _reject("IS_RECEIPT_CUSTODY", "artifact path escapes or aliases bundle custody")
        raw = resolved.read_bytes()
        if len(raw) != artifact["byte_count"] or _digest(raw) != artifact["digest"]:
            status = "FAIL"
            errors.append({"code": "IS_RECEIPT_ARTIFACT_MISMATCH", "message": f"artifact bytes differ: {relative}", "retriable": False})
    return status, errors


def verify_bundle(receipt_path: str | Path, bundle_root: str | Path, expected_digest: str | None) -> dict[str, Any]:
    _validate_implementation_lock()
    path = Path(receipt_path).resolve(strict=False)
    root = Path(bundle_root).resolve(strict=False)
    receipt = _read_json(path)
    _authority_digest, artifacts = _validate_structure(receipt)
    actual = _digest(canonical_bytes(receipt))
    if expected_digest is not None:
        _sha(expected_digest, "expected receipt digest")
    artifact_status, errors = _artifact_state(receipt, artifacts, root)
    if expected_digest is None:
        identity = "UNBOUND"
        verdict = "INCONCLUSIVE"
        errors.insert(0, {"code": "IS_RECEIPT_IDENTITY_UNBOUND", "message": "expected receipt digest is required for PASS", "retriable": False})
    elif actual != expected_digest:
        identity = "MISMATCH"
        verdict = "INVALID"
        errors.insert(0, {"code": "IS_RECEIPT_IDENTITY_MISMATCH", "message": "receipt digest differs from expected identity", "retriable": False})
    else:
        identity = "MATCH"
        verdict = "PASS" if artifact_status == "PASS" else artifact_status
    return {
        "schema_version": "incidentseal-receipt-verification/v1",
        "receipt_digest": actual,
        "expected_receipt_digest": expected_digest,
        "identity_status": identity,
        "schema_status": "PASS",
        "semantic_status": "PASS",
        "chain_status": "PASS",
        "artifact_status": artifact_status,
        "verification_verdict": verdict,
        "run_lifecycle": receipt["run"]["lifecycle"],
        "run_verdict": receipt["run"]["verdict"],
        "event_count": receipt["event_chain"]["event_count"],
        "errors": errors,
    }


def materialize_bundle(receipt_path: str | Path, source_root: str | Path, output_root: str | Path) -> dict[str, Any]:
    _validate_implementation_lock()
    receipt_source = Path(receipt_path).resolve(strict=True)
    source = Path(source_root).resolve(strict=True)
    output = Path(output_root).resolve(strict=False)
    forbidden = _forbidden_custody(output)
    if forbidden is not None:
        _reject("IS_RECEIPT_CUSTODY", forbidden)
    receipt = _read_json(receipt_source)
    _authority_digest, artifacts = _validate_structure(receipt)
    artifact_status, _errors = _artifact_state(receipt, artifacts, source)
    if artifact_status != "PASS":
        _reject("IS_RECEIPT_ARTIFACT", "source bundle artifacts do not pass")
    digest = _digest(canonical_bytes(receipt))
    output.mkdir(parents=True, exist_ok=True)
    output_resolved = output.resolve(strict=True)
    reparse = _reparse_component(output_resolved.absolute())
    if reparse is not None:
        _reject("IS_RECEIPT_CUSTODY", f"output custody contains a reparse point: {reparse}")
    final = output_resolved / "sha256" / digest.removeprefix("sha256:")
    final.parent.mkdir(parents=True, exist_ok=True)
    if final.exists():
        verified = verify_bundle(final / "receipt.json", final, digest)
        if verified["verification_verdict"] != "PASS":
            _reject("IS_RECEIPT_CONFLICT", "existing content-addressed bundle differs")
        return {"receipt_digest": digest, "bundle_path": str(final), "created": False, "idempotent": True, "verification": verified}
    staging = final.parent / f".{digest.removeprefix('sha256:')}.{uuid.uuid4().hex}.tmp"
    try:
        staging.mkdir()
        receipt_target = staging / "receipt.json"
        with receipt_target.open("xb") as receipt_stream:
            receipt_stream.write(canonical_bytes(receipt) + b"\n")
            receipt_stream.flush()
            os.fsync(receipt_stream.fileno())
        for artifact in artifacts:
            relative = Path(*artifact["path"].split("/"))
            source_artifact = source / relative
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source_artifact.open("rb") as input_stream, target.open("xb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        os.replace(staging, final)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    verified = verify_bundle(final / "receipt.json", final, digest)
    if verified["verification_verdict"] != "PASS":
        _reject("IS_RECEIPT_WRITE_VERIFY", "new bundle failed independent verification")
    return {"receipt_digest": digest, "bundle_path": str(final), "created": True, "idempotent": False, "verification": verified}
