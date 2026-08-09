"""Strict IncidentSeal workflow manifest parsing and canonicalization."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn


SAFE_INTEGER = 9_007_199_254_740_991
ALGORITHM = "RFC8785-JCS"
PROFILE = "incidentseal-workflow-v1-i-json"

TOP_LEVEL_REQUIRED = {
    "schema_version",
    "workflow_id",
    "revision",
    "repository",
    "claim",
    "security",
    "steps",
    "evidence_policy",
}
TOP_LEVEL_ALLOWED = TOP_LEVEL_REQUIRED | {"description"}
STEP_REQUIRED = {
    "id",
    "runner",
    "command",
    "cwd",
    "depends_on",
    "timeout_seconds",
    "expected_exit_codes",
    "inputs",
    "outputs",
    "network",
    "capture",
}
SECURITY = {
    "container_engine_control": "host-cli-only",
    "docker_socket": "denied",
    "privileged": False,
    "host_network": False,
    "runtime_egress": "denied",
    "secrets": "denied",
    "host_mount_mode": "staged-read-only",
}
EVIDENCE_POLICY = {
    "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
    "preserve_lifecycle": [
        "queued",
        "running",
        "completed",
        "cancelled",
        "failed",
        "stale",
        "superseded",
    ],
    "retain_attempts": "all",
}
RUNNERS = {"host", "python", "node", "postgresql", "compose-probe", "receipt-verifier"}
CAPTURE_MODES = {"full", "hash", "none"}

ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
INTEGER_TOKEN_RE = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")
RELATIVE_PATH_CHARS_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class ManifestDocument:
    """A validated manifest and its stable identity."""

    path: Path
    value: dict[str, Any]
    canonical: bytes
    digest: str


class ManifestError(ValueError):
    """A stable, agent-readable manifest rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ManifestReadError(OSError):
    """A stable local-input read failure."""

    code = "IS_MANIFEST_READ"


def _reject(code: str, message: str) -> NoReturn:
    raise ManifestError(code, message)


def _reject_float(token: str) -> Any:
    _reject("IS_MANIFEST_NUMBER_DOMAIN", f"non-integer number token: {token}")


def _parse_int(token: str) -> int:
    if not INTEGER_TOKEN_RE.fullmatch(token):
        _reject("IS_MANIFEST_NUMBER_DOMAIN", f"non-canonical integer token: {token}")
    value = int(token)
    if abs(value) > SAFE_INTEGER:
        _reject("IS_MANIFEST_NUMBER_DOMAIN", f"integer outside I-JSON safe range: {token}")
    return value


def _reject_constant(token: str) -> Any:
    _reject("IS_MANIFEST_NUMBER_DOMAIN", f"invalid JSON numeric constant: {token}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject("IS_MANIFEST_DUPLICATE_KEY", f"duplicate object name: {key}")
        value[key] = item
    return value


def _reject_lone_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            _reject("IS_MANIFEST_UNICODE", "lone Unicode surrogate")
        return
    if isinstance(value, list):
        for item in value:
            _reject_lone_surrogates(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_lone_surrogates(key)
            _reject_lone_surrogates(item)


def strict_load_bytes(raw: bytes) -> Any:
    """Parse strict UTF-8 JSON while rejecting ambiguous numeric and object forms."""

    if raw.startswith(b"\xef\xbb\xbf"):
        _reject("IS_MANIFEST_ENCODING", "UTF-8 byte-order mark is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ManifestError("IS_MANIFEST_ENCODING", "manifest is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except ManifestError:
        raise
    except json.JSONDecodeError as error:
        raise ManifestError(
            "IS_MANIFEST_JSON",
            f"invalid JSON at line {error.lineno}, column {error.colno}",
        ) from error
    _reject_lone_surrogates(value)
    return value


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 80 and ID_RE.fullmatch(value) is not None


def _valid_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 260:
        return False
    if value.startswith("/") or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return False
    if RELATIVE_PATH_CHARS_RE.fullmatch(value) is None:
        return False
    parts = value.split("/")
    return all(part not in {"", ".."} for part in parts)


def _schema_error(message: str) -> NoReturn:
    _reject("IS_MANIFEST_SCHEMA", message)


def _json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item) for left_item, right_item in zip(left, right)
        )
    return bool(left == right)


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _schema_error(f"{label} properties do not match incidentseal-workflow/v1")
    return value


def _require_unique_list(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _schema_error(f"{label} must be an array with at most {maximum} entries")
    if any(value[index] == earlier for index, item in enumerate(value) for earlier in value[:index]):
        _schema_error(f"{label} entries must be unique")
    return value


def validate_manifest(value: Any) -> dict[str, Any]:
    """Validate the exact closed IncidentSeal workflow v1 contract."""

    if not isinstance(value, dict):
        _schema_error("manifest must be an object")
    keys = set(value)
    if not TOP_LEVEL_REQUIRED <= keys or not keys <= TOP_LEVEL_ALLOWED:
        _schema_error("top-level required or allowed properties do not match v1")
    if value["schema_version"] != "incidentseal-workflow/v1":
        _schema_error("schema_version must be incidentseal-workflow/v1")
    if not _valid_id(value["workflow_id"]):
        _schema_error("workflow_id is invalid")
    revision = value["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or not 1 <= revision <= SAFE_INTEGER:
        _schema_error("revision is invalid")
    if "description" in value and (
        not isinstance(value["description"], str) or not 1 <= len(value["description"]) <= 500
    ):
        _schema_error("description is invalid")
    if not _json_equal(value["security"], SECURITY):
        _schema_error("security boundary differs from the v1 fixed boundary")
    if not _json_equal(value["evidence_policy"], EVIDENCE_POLICY):
        _schema_error("evidence policy does not preserve all required states")

    repository = _require_exact_keys(
        value["repository"], {"remote", "commit", "tree_digest"}, "repository"
    )
    remote = repository["remote"]
    if (
        not isinstance(remote, str)
        or len(remote) > 500
        or re.fullmatch(r"https://[^\s]+", remote) is None
    ):
        _schema_error("repository remote must be a bounded HTTPS URL")
    if not isinstance(repository["commit"], str) or COMMIT_RE.fullmatch(repository["commit"]) is None:
        _schema_error("repository commit is invalid")
    if (
        not isinstance(repository["tree_digest"], str)
        or SHA256_RE.fullmatch(repository["tree_digest"]) is None
    ):
        _schema_error("repository tree digest is invalid")

    steps = value["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        _schema_error("steps must contain 1 to 64 entries")
    step_ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    for step_value in steps:
        step = _require_exact_keys(step_value, STEP_REQUIRED, "step")
        step_id = step["id"]
        if not _valid_id(step_id) or step_id in step_ids:
            _schema_error("step ids must be valid and unique")
        step_ids.append(step_id)
        if not isinstance(step["runner"], str) or step["runner"] not in RUNNERS:
            _schema_error("runner is invalid")
        command = step["command"]
        if (
            not isinstance(command, list)
            or not 1 <= len(command) <= 64
            or not all(
                isinstance(argument, str) and 1 <= len(argument) <= 4096 and "\x00" not in argument
                for argument in command
            )
        ):
            _schema_error("command must be a bounded non-empty argument vector")
        if not _valid_relative_path(step["cwd"]):
            _schema_error("cwd must be a safe relative path")
        for field in ("inputs", "outputs"):
            paths = _require_unique_list(step[field], field, 128)
            if not all(_valid_relative_path(path) for path in paths):
                _schema_error(f"{field} must contain safe relative paths")
        depends_on = _require_unique_list(step["depends_on"], "depends_on", 64)
        if not all(_valid_id(dependency) for dependency in depends_on):
            _schema_error("depends_on contains an invalid step id")
        dependencies[step_id] = depends_on
        timeout = step["timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
            _schema_error("timeout_seconds is invalid")
        exit_codes = step["expected_exit_codes"]
        if (
            not isinstance(exit_codes, list)
            or not 1 <= len(exit_codes) <= 16
            or any(exit_codes[index] == earlier for index, code in enumerate(exit_codes) for earlier in exit_codes[:index])
            or any(isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255 for code in exit_codes)
        ):
            _schema_error("expected_exit_codes is invalid")
        if step["network"] != "none":
            _schema_error("step network must be none")
        capture = _require_exact_keys(step["capture"], {"stdout", "stderr", "max_bytes"}, "capture")
        if (
            not isinstance(capture["stdout"], str)
            or capture["stdout"] not in CAPTURE_MODES
            or not isinstance(capture["stderr"], str)
            or capture["stderr"] not in CAPTURE_MODES
        ):
            _schema_error("capture mode is invalid")
        maximum = capture["max_bytes"]
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 <= maximum <= 104_857_600:
            _schema_error("capture max_bytes is invalid")

    known = set(step_ids)
    for step_id, prerequisites in dependencies.items():
        if step_id in prerequisites or not set(prerequisites) <= known:
            _schema_error("step dependency is missing or self-referential")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step_id: str) -> None:
        if step_id in visiting:
            _schema_error("step dependency graph contains a cycle")
        if step_id in visited:
            return
        visiting.add(step_id)
        for prerequisite in dependencies[step_id]:
            visit(prerequisite)
        visiting.remove(step_id)
        visited.add(step_id)

    for step_id in step_ids:
        visit(step_id)

    claim = _require_exact_keys(value["claim"], {"id", "statement", "required_steps"}, "claim")
    if not _valid_id(claim["id"]):
        _schema_error("claim id is invalid")
    if not isinstance(claim["statement"], str) or not 1 <= len(claim["statement"]) <= 1000:
        _schema_error("claim statement is invalid")
    required_steps = _require_unique_list(claim["required_steps"], "claim required_steps", 64)
    if not required_steps or not all(_valid_id(step_id) for step_id in required_steps):
        _schema_error("claim required_steps is invalid")
    if not set(required_steps) <= known:
        _schema_error("claim required_steps must reference declared steps")
    return value


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > SAFE_INTEGER:
            _reject("IS_MANIFEST_NUMBER_DOMAIN", "integer outside I-JSON safe range")
        return str(value)
    if isinstance(value, float):
        _reject("IS_MANIFEST_NUMBER_DOMAIN", "floating-point values are forbidden")
    if isinstance(value, str):
        _reject_lone_surrogates(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            _reject("IS_MANIFEST_JSON", "object names must be strings")
        names = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(
            f"{_canonical_text(name)}:{_canonical_text(value[name])}" for name in names
        ) + "}"
    _reject("IS_MANIFEST_JSON", f"unsupported JSON value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Serialize an admitted I-JSON value using RFC 8785 property ordering."""

    _reject_lone_surrogates(value)
    return _canonical_text(value).encode("utf-8")


def load_manifest(path_value: str | Path) -> ManifestDocument:
    """Read, validate, canonicalize, and identify one workflow manifest."""

    path = Path(path_value).expanduser().resolve(strict=False)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ManifestReadError(f"could not read manifest: {path}") from error
    value = strict_load_bytes(raw)
    validated = validate_manifest(value)
    canonical = canonical_bytes(validated)
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return ManifestDocument(path=path, value=validated, canonical=canonical, digest=digest)
