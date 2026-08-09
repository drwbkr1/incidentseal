"""Interactive, operator-only manifest approval surface."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO

from .approval import (
    ApprovalStore,
    _has_reparse_or_symlink,
    _inside,
    _windows_system_directory,
    default_approval_root,
    find_repository_root,
    manifest_relative_path,
    permissions_restrictive,
    repository_key,
)
from .manifest import ManifestDocument, ManifestError, ManifestReadError, load_manifest


EXIT_SUCCESS = 0
EXIT_CANCELLED = 20
EXIT_USAGE = 64
EXIT_IO = 74
EXIT_FORBIDDEN = 77


@dataclass(frozen=True)
class ApprovalWriteResult:
    approval_path: Path
    approval_file_digest: str
    superseded_path: Path | None


class ApprovalWriteError(RuntimeError):
    pass


def _current_principal() -> str:
    if os.name == "nt":
        executable = _windows_system_directory() / "whoami.exe"
        try:
            result = subprocess.run(
                [str(executable)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ApprovalWriteError("current Windows principal is unavailable") from error
        principal = result.stdout.strip()
        if result.returncode != 0 or not principal:
            raise ApprovalWriteError("current Windows principal is unavailable")
        return principal
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError) as error:
        raise ApprovalWriteError("current POSIX principal is unavailable") from error


def _safe_planned_root(root: Path, repository_root: Path, forbidden_roots: Iterable[Path]) -> Path:
    lexical = Path(os.path.abspath(root))
    resolved = lexical.resolve(strict=False)
    repository = repository_root.resolve(strict=False)
    if _inside(resolved, repository) or _inside(repository, resolved):
        raise ApprovalWriteError("approval root overlaps repository custody")
    for forbidden in forbidden_roots:
        boundary = forbidden.resolve(strict=False)
        if _inside(resolved, boundary) or _inside(boundary, resolved):
            raise ApprovalWriteError("approval root overlaps forbidden custody")
    current = lexical
    while True:
        if current.exists() or current.is_symlink():
            if _has_reparse_or_symlink(current):
                raise ApprovalWriteError("approval root path contains a symlink or reparse point")
        if current.parent == current:
            break
        current = current.parent
    return lexical


def _ensure_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(path, 0o700)
    except OSError as error:
        raise ApprovalWriteError(f"could not create approval directory: {path}") from error
    if not path.is_dir() or _has_reparse_or_symlink(path) or not permissions_restrictive(path):
        raise ApprovalWriteError(f"approval directory custody is unsafe: {path}")


def _select_exact_child(directory: Path, expected_name: str, *, create_directory: bool) -> Path:
    try:
        matches = [candidate for candidate in directory.iterdir() if candidate.name.casefold() == expected_name.casefold()]
    except OSError as error:
        raise ApprovalWriteError(f"approval directory is unreadable: {directory}") from error
    if len(matches) > 1 or (matches and matches[0].name != expected_name):
        raise ApprovalWriteError(f"approval custody is case-ambiguous: {expected_name}")
    if matches:
        selected = matches[0]
        if create_directory and (
            not selected.is_dir() or _has_reparse_or_symlink(selected) or not permissions_restrictive(selected)
        ):
            raise ApprovalWriteError(f"approval directory custody is unsafe: {selected}")
        return selected
    selected = directory / expected_name
    if create_directory:
        _ensure_directory(selected)
    return selected


def _exclusive_write(path: Path, raw: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ApprovalWriteError(f"could not create approval file: {path}") from error
    if _has_reparse_or_symlink(path) or not permissions_restrictive(path):
        try:
            path.unlink()
        except OSError:
            pass
        raise ApprovalWriteError(f"approval file custody is unsafe: {path}")


def _record_bytes(
    document: ManifestDocument,
    relative_manifest_path: str,
    *,
    approved_at: datetime,
    principal: str,
) -> bytes:
    record = {
        "schema_version": "incidentseal-manifest-approval/v1",
        "approval_id": str(uuid.uuid4()),
        "workflow_id": document.value["workflow_id"],
        "manifest_schema_version": document.value["schema_version"],
        "repository_remote": document.value["repository"]["remote"],
        "manifest_path": relative_manifest_path,
        "manifest_digest": document.digest,
        "approved_at_utc": approved_at.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": None,
        "approved_by": {"kind": "operator", "local_principal": principal},
    }
    return (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _retain_superseded(
    repository_directory: Path,
    workflow_id: str,
    existing: bytes,
    approved_at: datetime,
) -> Path:
    superseded_root = repository_directory / "superseded" / workflow_id
    _ensure_directory(superseded_root)
    digest = hashlib.sha256(existing).hexdigest()
    timestamp = approved_at.astimezone(UTC).replace(microsecond=0).strftime("%Y%m%dT%H%M%SZ")
    destination = superseded_root / f"{timestamp}-{digest}.json"
    if destination.exists():
        try:
            if destination.read_bytes() == existing:
                return destination
        except OSError as error:
            raise ApprovalWriteError("existing superseded record is unreadable") from error
        raise ApprovalWriteError("superseded record path collision")
    _exclusive_write(destination, existing)
    return destination


def _restore_after_failed_verification(
    target: Path,
    existing: bytes | None,
    repository_directory: Path,
    workflow_id: str,
) -> None:
    try:
        if existing is None:
            target.unlink(missing_ok=True)
            return
        rollback = repository_directory / f".{workflow_id}.{uuid.uuid4().hex}.rollback"
        _exclusive_write(rollback, existing)
        try:
            os.replace(rollback, target)
        finally:
            if rollback.exists():
                rollback.unlink()
    except (OSError, ApprovalWriteError) as error:
        raise ApprovalWriteError("written approval failed verification and rollback failed") from error


def write_approval(
    document: ManifestDocument,
    repository_root: Path,
    *,
    root: Path | None = None,
    forbidden_roots: Iterable[Path] = (),
    approved_at: datetime | None = None,
    principal: str | None = None,
    expected_current_file_digest: str | None,
) -> ApprovalWriteResult:
    """Write one operator-authorized approval after interactive confirmation."""

    relative = manifest_relative_path(document, repository_root)
    if relative is None:
        raise ApprovalWriteError("manifest is outside repository custody")
    timestamp = datetime.now(UTC).replace(microsecond=0) if approved_at is None else approved_at.astimezone(UTC)
    operator = _current_principal() if principal is None else principal
    if not operator or len(operator) > 200:
        raise ApprovalWriteError("operator principal is invalid")
    approval_root = _safe_planned_root(default_approval_root() if root is None else root, repository_root, forbidden_roots)
    _ensure_directory(approval_root)
    _safe_planned_root(approval_root, repository_root, forbidden_roots)

    directory_name = repository_key(document.value["repository"]["remote"])
    repository_directory = _select_exact_child(approval_root, directory_name, create_directory=True)
    target = _select_exact_child(
        repository_directory,
        document.value["workflow_id"] + ".json",
        create_directory=False,
    )
    existing: bytes | None = None
    if target.exists():
        if not target.is_file() or _has_reparse_or_symlink(target) or not permissions_restrictive(target):
            raise ApprovalWriteError("existing approval file custody is unsafe")
        try:
            existing = target.read_bytes()
        except OSError as error:
            raise ApprovalWriteError("existing approval file is unreadable") from error
    observed_existing_digest = None if existing is None else "sha256:" + hashlib.sha256(existing).hexdigest()
    if expected_current_file_digest is None:
        if observed_existing_digest is not None:
            raise ApprovalWriteError("approval changed after operator review")
    elif observed_existing_digest is None or not hmac.compare_digest(
        expected_current_file_digest,
        observed_existing_digest,
    ):
        raise ApprovalWriteError("approval changed after operator review")

    raw = _record_bytes(document, relative, approved_at=timestamp, principal=operator)
    temporary = repository_directory / f".{document.value['workflow_id']}.{uuid.uuid4().hex}.tmp"
    _exclusive_write(temporary, raw)
    superseded: Path | None = None
    try:
        if existing is not None:
            superseded = _retain_superseded(
                repository_directory,
                document.value["workflow_id"],
                existing,
                timestamp,
            )
        os.replace(temporary, target)
        temporary = Path()
    except (OSError, ApprovalWriteError) as error:
        if temporary != Path() and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
        if isinstance(error, ApprovalWriteError):
            raise
        raise ApprovalWriteError("atomic approval replacement failed") from error

    inspection = ApprovalStore(approval_root, repository_root, forbidden_roots=forbidden_roots).inspect(
        document,
        relative,
        now=timestamp,
    )
    if inspection.status != "MATCH" or inspection.approval_path != target:
        _restore_after_failed_verification(
            target,
            existing,
            repository_directory,
            document.value["workflow_id"],
        )
        raise ApprovalWriteError("written approval did not pass independent inspection; prior state restored")
    return ApprovalWriteResult(target, inspection.approval_file_digest or "", superseded)


def approve_interactive(
    manifest_path: str,
    *,
    input_stream: TextIO,
    output_stream: TextIO,
    error_stream: TextIO,
    root: Path | None = None,
    repository_root: Path | None = None,
    forbidden_roots: Iterable[Path] = (),
    approved_at: datetime | None = None,
    principal: str | None = None,
) -> int:
    if not input_stream.isatty() or not output_stream.isatty():
        error_stream.write("IncidentSeal refused approval: an interactive terminal is required.\n")
        return EXIT_FORBIDDEN
    try:
        document = load_manifest(manifest_path)
    except ManifestReadError as error:
        error_stream.write(f"IncidentSeal could not read the manifest: {error}\n")
        return EXIT_IO
    except ManifestError as error:
        error_stream.write(f"IncidentSeal rejected the manifest ({error.code}): {error}\n")
        return 12
    repo_root = find_repository_root(document.path) if repository_root is None else repository_root
    if repo_root is None:
        error_stream.write("IncidentSeal refused approval: the manifest is not in a Git worktree.\n")
        return EXIT_FORBIDDEN
    relative = manifest_relative_path(document, repo_root)
    if relative is None:
        error_stream.write("IncidentSeal refused approval: the manifest is outside repository custody.\n")
        return EXIT_FORBIDDEN

    approval_root = default_approval_root() if root is None else root
    current = ApprovalStore(approval_root, repo_root, forbidden_roots=forbidden_roots).inspect(
        document,
        relative,
        now=approved_at,
    )
    if current.status == "INVALID":
        error_stream.write(f"IncidentSeal refused approval: {current.message}\n")
        return EXIT_FORBIDDEN
    if current.status == "MATCH":
        output_stream.write("IncidentSeal manifest already matches the current operator approval.\n")
        return EXIT_SUCCESS

    output_stream.write("IncidentSeal operator manifest approval\n")
    output_stream.write(f"Manifest: {document.path}\n")
    output_stream.write(f"Workflow: {document.value['workflow_id']}\n")
    output_stream.write(f"Repository: {document.value['repository']['remote']}\n")
    output_stream.write(f"Relative path: {relative}\n")
    output_stream.write(f"Canonical digest: {document.digest}\n")
    output_stream.write(f"Current approval status: {current.status}\n")
    if current.differences:
        output_stream.write("Differences: " + ", ".join(current.differences) + "\n")
    output_stream.write("Type the full canonical digest to approve this exact manifest: ")
    output_stream.flush()
    try:
        confirmation = input_stream.readline()
    except (OSError, KeyboardInterrupt):
        error_stream.write("\nIncidentSeal approval cancelled.\n")
        return EXIT_CANCELLED
    if confirmation == "" or confirmation.rstrip("\r\n") != document.digest:
        error_stream.write("IncidentSeal approval cancelled: digest confirmation did not match.\n")
        return EXIT_CANCELLED
    try:
        refreshed = load_manifest(document.path)
    except (ManifestError, ManifestReadError):
        error_stream.write("IncidentSeal approval failed closed: the manifest changed after review.\n")
        return EXIT_FORBIDDEN
    if not hmac.compare_digest(refreshed.digest, document.digest):
        error_stream.write("IncidentSeal approval failed closed: the manifest changed after review.\n")
        return EXIT_FORBIDDEN
    refreshed_current = ApprovalStore(approval_root, repo_root, forbidden_roots=forbidden_roots).inspect(
        refreshed,
        relative,
        now=approved_at,
    )
    displayed_snapshot = (
        current.status,
        current.approved_digest,
        current.approval_file_digest,
        current.differences,
    )
    refreshed_snapshot = (
        refreshed_current.status,
        refreshed_current.approved_digest,
        refreshed_current.approval_file_digest,
        refreshed_current.differences,
    )
    if displayed_snapshot != refreshed_snapshot:
        error_stream.write("IncidentSeal approval failed closed: approval state changed after review.\n")
        return EXIT_FORBIDDEN
    try:
        result = write_approval(
            refreshed,
            repo_root,
            root=approval_root,
            forbidden_roots=forbidden_roots,
            approved_at=approved_at,
            principal=principal,
            expected_current_file_digest=refreshed_current.approval_file_digest,
        )
    except ApprovalWriteError as error:
        error_stream.write(f"IncidentSeal approval failed closed: {error}\n")
        return EXIT_FORBIDDEN
    output_stream.write(f"Approved: {result.approval_path}\n")
    output_stream.write(f"Approval record digest: {result.approval_file_digest}\n")
    if result.superseded_path is not None:
        output_stream.write(f"Superseded record retained: {result.superseded_path}\n")
    return EXIT_SUCCESS


def main(
    argv: Sequence[str] | None = None,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    stdin = sys.stdin if input_stream is None else input_stream
    stdout = sys.stdout if output_stream is None else output_stream
    stderr = sys.stderr if error_stream is None else error_stream
    if len(arguments) != 2 or arguments[0] != "--manifest" or not arguments[1]:
        stderr.write("Usage: incidentseal operator approve-manifest --manifest PATH\n")
        return EXIT_USAGE
    return approve_interactive(
        arguments[1],
        input_stream=stdin,
        output_stream=stdout,
        error_stream=stderr,
    )
