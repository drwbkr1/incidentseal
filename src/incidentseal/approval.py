"""Read-only inspection of operator-owned IncidentSeal manifest approvals."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable

from .manifest import ManifestDocument, ManifestError, strict_load_bytes


APPROVAL_SCHEMA_VERSION = "incidentseal-manifest-approval/v1"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HTTPS_RE = re.compile(r"^https://[^\s]+$")
RELATIVE_PATH_CHARS_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

APPROVAL_REQUIRED = {
    "schema_version",
    "approval_id",
    "workflow_id",
    "manifest_schema_version",
    "repository_remote",
    "manifest_path",
    "manifest_digest",
    "approved_at_utc",
    "expires_at_utc",
    "approved_by",
}
APPROVAL_ALLOWED = APPROVAL_REQUIRED | {"note"}


@dataclass(frozen=True)
class ApprovalResult:
    """One fail-closed approval comparison result."""

    status: str
    approved_digest: str | None
    approval_path: Path | None
    approval_file_digest: str | None
    differences: tuple[str, ...]
    error_code: str | None
    message: str | None

    @property
    def approved(self) -> bool:
        return self.status == "MATCH"

    def evidence(self) -> list[dict[str, str]]:
        if self.approval_path is None or self.approval_file_digest is None:
            return []
        return [
            {
                "kind": "artifact",
                "path": str(self.approval_path),
                "digest": self.approval_file_digest,
            }
        ]


def default_approval_root() -> Path:
    """Return the fixed platform approval root without creating it."""

    if os.name == "nt":
        return _windows_local_app_data() / "IncidentSeal" / "approvals" / "v1"
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "incidentseal" / "approvals" / "v1"
    return Path.home() / ".local" / "state" / "incidentseal" / "approvals" / "v1"


def repository_key(repository_remote: str) -> str:
    return hashlib.sha256(repository_remote.encode("utf-8")).hexdigest()


def find_repository_root(manifest_path: Path) -> Path | None:
    """Find the containing Git worktree without invoking Git or changing state."""

    current = manifest_path.resolve(strict=False).parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def manifest_relative_path(document: ManifestDocument, repository_root: Path) -> str | None:
    try:
        relative = document.path.resolve(strict=False).relative_to(repository_root.resolve(strict=False))
    except ValueError:
        return None
    value = relative.as_posix()
    return value if _valid_relative_path(value) else None


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 260:
        return False
    if value.startswith("/") or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return False
    if RELATIVE_PATH_CHARS_RE.fullmatch(value) is None:
        return False
    return all(part not in {"", ".."} for part in value.split("/"))


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None
    return parsed if parsed.strftime(TIMESTAMP_FORMAT) == value else None


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _has_reparse_or_symlink(path: Path) -> bool:
    try:
        information = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(information.st_mode):
        return True
    attributes = getattr(information, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _windows_system_directory() -> Path:
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    except (AttributeError, OSError) as error:
        raise RuntimeError("Windows system directory is unavailable") from error
    if length <= 0 or length >= len(buffer):
        raise RuntimeError("Windows system directory is unavailable")
    return Path(buffer.value)


def _windows_local_app_data() -> Path:
    try:
        import ctypes
        from ctypes import wintypes

        class Guid(ctypes.Structure):
            _fields_ = [
                ("data1", wintypes.DWORD),
                ("data2", wintypes.WORD),
                ("data3", wintypes.WORD),
                ("data4", ctypes.c_ubyte * 8),
            ]

        raw = uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le
        folder_id = Guid.from_buffer_copy(raw)
        output = ctypes.c_wchar_p()
        result = ctypes.windll.shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id),
            0,
            None,
            ctypes.byref(output),
        )
        if result != 0 or not output.value:
            raise RuntimeError("Windows Local AppData is unavailable")
        try:
            return Path(output.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(output)
    except (AttributeError, OSError, ValueError) as error:
        raise RuntimeError("Windows Local AppData is unavailable") from error


def _existing_chain(path: Path) -> Iterable[Path]:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            yield current
        if current.parent == current:
            break
        current = current.parent


def _windows_permissions_restrictive(path: Path) -> bool:
    username = os.environ.get("USERNAME", "").casefold()
    domain = os.environ.get("USERDOMAIN", "").casefold()
    current_names = {username}
    if username and domain:
        current_names.add(f"{domain}\\{username}")
    owner_environment = os.environ.copy()
    owner_environment["INCIDENTSEAL_ACL_PATH"] = str(path)
    try:
        system_directory = _windows_system_directory()
        powershell = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        icacls = system_directory / "icacls.exe"
        owner_result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Acl -LiteralPath $env:INCIDENTSEAL_ACL_PATH).Owner",
            ],
            env=owner_environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    owner = owner_result.stdout.strip().casefold()
    if owner_result.returncode != 0 or owner not in current_names:
        return False
    try:
        result = subprocess.run(
            [str(icacls), str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    allowed_writers = current_names | {
        "nt authority\\system",
        "builtin\\administrators",
        "creator owner",
        "owner rights",
        "s-1-5-18",
        "s-1-5-32-544",
    }
    write_markers = ("(F)", "(M)", "(W)", "(WD)", "(AD)", "(DC)", "(WO)")
    current_user_can_write = False
    path_text = str(path)
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("successfully processed"):
            continue
        if line.casefold().startswith(path_text.casefold()):
            line = line[len(path_text):].lstrip()
        if ":" not in line:
            continue
        principal, rights = line.split(":", 1)
        principal = principal.strip().casefold()
        can_write = any(marker in rights for marker in write_markers)
        if not can_write:
            continue
        if principal not in allowed_writers:
            return False
        if principal in current_names or principal == "owner rights":
            current_user_can_write = True
    return current_user_can_write


def _posix_permissions_restrictive(path: Path) -> bool:
    try:
        information = path.stat()
    except OSError:
        return False
    if hasattr(os, "getuid") and information.st_uid != os.getuid():
        return False
    if sys.platform == "darwin":
        return False
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, OSError):
        return False
    if "system.posix_acl_access" in attributes:
        return False
    return information.st_mode & 0o022 == 0


def permissions_restrictive(path: Path) -> bool:
    return _windows_permissions_restrictive(path) if os.name == "nt" else _posix_permissions_restrictive(path)


def _invalid(
    message: str,
    *,
    path: Path | None = None,
    file_digest: str | None = None,
) -> ApprovalResult:
    return ApprovalResult(
        status="INVALID",
        approved_digest=None,
        approval_path=path,
        approval_file_digest=file_digest,
        differences=("custody_or_record",),
        error_code="IS_APPROVAL_INVALID",
        message=message,
    )


def _validate_approval(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not APPROVAL_REQUIRED <= set(value) or not set(value) <= APPROVAL_ALLOWED:
        raise ValueError("approval properties do not match v1")
    if value["schema_version"] != APPROVAL_SCHEMA_VERSION:
        raise ValueError("approval schema_version is invalid")
    if not isinstance(value["approval_id"], str) or UUID4_RE.fullmatch(value["approval_id"]) is None:
        raise ValueError("approval_id is invalid")
    if (
        not isinstance(value["workflow_id"], str)
        or len(value["workflow_id"]) > 80
        or ID_RE.fullmatch(value["workflow_id"]) is None
    ):
        raise ValueError("workflow_id is invalid")
    if value["manifest_schema_version"] != "incidentseal-workflow/v1":
        raise ValueError("manifest_schema_version is invalid")
    remote = value["repository_remote"]
    if not isinstance(remote, str) or len(remote) > 500 or HTTPS_RE.fullmatch(remote) is None:
        raise ValueError("repository_remote is invalid")
    if not _valid_relative_path(value["manifest_path"]):
        raise ValueError("manifest_path is invalid")
    if not isinstance(value["manifest_digest"], str) or SHA256_RE.fullmatch(value["manifest_digest"]) is None:
        raise ValueError("manifest_digest is invalid")
    approved_at = _parse_timestamp(value["approved_at_utc"])
    if approved_at is None:
        raise ValueError("approved_at_utc is invalid")
    expires_at_value = value["expires_at_utc"]
    expires_at = None if expires_at_value is None else _parse_timestamp(expires_at_value)
    if expires_at_value is not None and expires_at is None:
        raise ValueError("expires_at_utc is invalid")
    if expires_at is not None and expires_at <= approved_at:
        raise ValueError("expires_at_utc must be later than approved_at_utc")
    approved_by = value["approved_by"]
    if not isinstance(approved_by, dict) or set(approved_by) != {"kind", "local_principal"}:
        raise ValueError("approved_by is invalid")
    if approved_by["kind"] != "operator":
        raise ValueError("approved_by.kind is invalid")
    principal = approved_by["local_principal"]
    if not isinstance(principal, str) or not 1 <= len(principal) <= 200:
        raise ValueError("approved_by.local_principal is invalid")
    if "note" in value and (not isinstance(value["note"], str) or len(value["note"]) > 1000):
        raise ValueError("note is invalid")
    return value


class ApprovalStore:
    """A read-only approval store view for agent-facing commands."""

    def __init__(
        self,
        root: Path,
        repository_root: Path,
        *,
        forbidden_roots: Iterable[Path] = (),
        permission_checker: Callable[[Path], bool] = permissions_restrictive,
    ) -> None:
        self.root = Path(os.path.abspath(root))
        self.resolved_root = self.root.resolve(strict=False)
        self.repository_root = Path(os.path.abspath(repository_root)).resolve(strict=False)
        self.forbidden_roots = tuple(Path(os.path.abspath(path)).resolve(strict=False) for path in forbidden_roots)
        self.permission_checker = permission_checker

    def _permissions_are_restrictive(self, path: Path) -> bool:
        try:
            return bool(self.permission_checker(path))
        except Exception:
            return False

    def inspect(
        self,
        document: ManifestDocument,
        relative_manifest_path: str,
        *,
        now: datetime | None = None,
    ) -> ApprovalResult:
        current_time = datetime.now(UTC).replace(microsecond=0) if now is None else now.astimezone(UTC)
        if _inside(self.resolved_root, self.repository_root) or _inside(self.repository_root, self.resolved_root):
            return _invalid("approval root overlaps repository custody")
        if any(
            _inside(self.resolved_root, forbidden) or _inside(forbidden, self.resolved_root)
            for forbidden in self.forbidden_roots
        ):
            return _invalid("approval root overlaps forbidden custody")
        if not self.root.exists():
            return ApprovalResult("MISSING", None, None, None, ("approval",), "IS_APPROVAL_MISSING", "approval is missing")
        if not self.root.is_dir():
            return _invalid("approval root is not a directory")
        for component in _existing_chain(self.root):
            if _has_reparse_or_symlink(component):
                return _invalid("approval root contains a symlink or reparse point")
        if not self._permissions_are_restrictive(self.root):
            return _invalid("approval root permissions are not restrictive")

        remote = document.value["repository"]["remote"]
        expected_directory_name = repository_key(remote)
        try:
            directory_matches = [
                candidate
                for candidate in self.root.iterdir()
                if candidate.name.casefold() == expected_directory_name.casefold()
            ]
        except OSError:
            return _invalid("approval root is unreadable")
        if not directory_matches:
            return ApprovalResult("MISSING", None, None, None, ("approval",), "IS_APPROVAL_MISSING", "approval is missing")
        if len(directory_matches) != 1 or directory_matches[0].name != expected_directory_name:
            return _invalid("approval repository directory is case-ambiguous")
        repository_directory = directory_matches[0]
        if not repository_directory.is_dir() or _has_reparse_or_symlink(repository_directory):
            return _invalid("approval repository directory is unsafe")
        if not self._permissions_are_restrictive(repository_directory):
            return _invalid("approval repository directory permissions are not restrictive")

        expected_filename = document.value["workflow_id"] + ".json"
        try:
            file_matches = [
                candidate
                for candidate in repository_directory.iterdir()
                if candidate.name.casefold() == expected_filename.casefold()
            ]
        except OSError:
            return _invalid("approval repository directory is unreadable")
        if not file_matches:
            return ApprovalResult("MISSING", None, None, None, ("approval",), "IS_APPROVAL_MISSING", "approval is missing")
        if len(file_matches) != 1 or file_matches[0].name != expected_filename:
            return _invalid("approval filename is case-ambiguous")
        approval_path = file_matches[0]
        if not approval_path.is_file() or _has_reparse_or_symlink(approval_path):
            return _invalid("approval file is unsafe", path=approval_path)
        if not self._permissions_are_restrictive(approval_path):
            return _invalid("approval file permissions are not restrictive", path=approval_path)
        try:
            raw = approval_path.read_bytes()
        except OSError:
            return _invalid("approval file is unreadable", path=approval_path)
        file_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        try:
            approval = _validate_approval(strict_load_bytes(raw))
        except (ManifestError, ValueError):
            return _invalid("approval record is invalid", path=approval_path, file_digest=file_digest)

        approved_at = _parse_timestamp(approval["approved_at_utc"])
        expires_at = None if approval["expires_at_utc"] is None else _parse_timestamp(approval["expires_at_utc"])
        if approved_at is None or approved_at > current_time:
            return _invalid("approval time is invalid", path=approval_path, file_digest=file_digest)

        differences: list[str] = []
        comparisons = {
            "workflow_id": document.value["workflow_id"],
            "manifest_schema_version": document.value["schema_version"],
            "repository_remote": remote,
            "manifest_path": relative_manifest_path,
        }
        for field, expected in comparisons.items():
            if approval[field] != expected:
                differences.append(field)
        if not hmac.compare_digest(approval["manifest_digest"], document.digest):
            differences.append("manifest_digest")
        approved_digest = approval["manifest_digest"]
        if differences:
            return ApprovalResult(
                "MISMATCH",
                approved_digest,
                approval_path,
                file_digest,
                tuple(differences),
                "IS_APPROVAL_MISMATCH",
                "approval bindings do not match the manifest",
            )
        if expires_at is not None and current_time >= expires_at:
            return ApprovalResult(
                "EXPIRED",
                approved_digest,
                approval_path,
                file_digest,
                ("expires_at_utc",),
                "IS_APPROVAL_EXPIRED",
                "approval is expired",
            )
        return ApprovalResult("MATCH", approved_digest, approval_path, file_digest, (), None, None)


def inspect_document(
    document: ManifestDocument,
    *,
    root: Path | None = None,
    repository_root: Path | None = None,
    forbidden_roots: Iterable[Path] = (),
    now: datetime | None = None,
    permission_checker: Callable[[Path], bool] = permissions_restrictive,
) -> ApprovalResult:
    repo_root = find_repository_root(document.path) if repository_root is None else repository_root
    if repo_root is None:
        return _invalid("manifest is not inside a discoverable Git worktree")
    relative = manifest_relative_path(document, repo_root)
    if relative is None:
        return _invalid("manifest path is outside repository custody")
    try:
        approval_root = default_approval_root() if root is None else root
    except RuntimeError:
        return _invalid("platform approval root is unavailable")
    return ApprovalStore(
        approval_root,
        repo_root,
        forbidden_roots=forbidden_roots,
        permission_checker=permission_checker,
    ).inspect(document, relative, now=now)
