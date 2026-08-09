#!/usr/bin/env python3
"""Dependency-free invariant checks for the frozen IncidentSeal v1 contracts."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures" / "contracts"
SAFE_INTEGER = 9_007_199_254_740_991
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

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
RUNNERS = {"host", "python", "node", "postgresql", "compose-probe", "receipt-verifier"}
ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
INTEGER_TOKEN_RE = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")


class ContractError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject_float(token: str) -> Any:
    raise ContractError("IS_MANIFEST_NUMBER_DOMAIN", f"non-integer number token: {token}")


def _parse_int(token: str) -> int:
    if not INTEGER_TOKEN_RE.fullmatch(token):
        raise ContractError("IS_MANIFEST_NUMBER_DOMAIN", f"non-canonical integer token: {token}")
    value = int(token)
    if abs(value) > SAFE_INTEGER:
        raise ContractError("IS_MANIFEST_NUMBER_DOMAIN", f"integer outside I-JSON safe range: {token}")
    return value


def _reject_constant(token: str) -> Any:
    raise ContractError("IS_MANIFEST_NUMBER_DOMAIN", f"invalid JSON numeric constant: {token}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("IS_MANIFEST_DUPLICATE_KEY", f"duplicate object name: {key}")
        result[key] = value
    return result


def _reject_lone_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ContractError("IS_MANIFEST_UNICODE", "lone Unicode surrogate")
    elif isinstance(value, list):
        for item in value:
            _reject_lone_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_lone_surrogates(key)
            _reject_lone_surrogates(item)


def strict_load(path: Path) -> Any:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError("IS_MANIFEST_ENCODING", "UTF-8 byte-order mark is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError("IS_MANIFEST_ENCODING", str(error)) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except json.JSONDecodeError as error:
        raise ContractError("IS_MANIFEST_JSON", str(error)) from error
    _reject_lone_surrogates(value)
    return value


def _is_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 260:
        return False
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        return False
    return ".." not in value.split("/") and all(part not in {""} for part in value.split("/"))


def _schema_error(message: str) -> None:
    raise ContractError("IS_MANIFEST_SCHEMA", message)


def validate_manifest(value: Any) -> None:
    if not isinstance(value, dict):
        _schema_error("manifest must be an object")
    keys = set(value)
    if not TOP_LEVEL_REQUIRED <= keys or not keys <= TOP_LEVEL_ALLOWED:
        _schema_error("top-level required or allowed properties do not match v1")
    if value["schema_version"] != "incidentseal-workflow/v1":
        _schema_error("schema_version must be incidentseal-workflow/v1")
    if not isinstance(value["workflow_id"], str) or not ID_RE.fullmatch(value["workflow_id"]):
        _schema_error("workflow_id is invalid")
    revision = value["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or not 1 <= revision <= SAFE_INTEGER:
        _schema_error("revision is invalid")
    if value["security"] != SECURITY:
        _schema_error("security boundary differs from the v1 fixed boundary")
    if value["evidence_policy"] != EVIDENCE_POLICY:
        _schema_error("evidence policy does not preserve all required states")

    repository = value["repository"]
    if not isinstance(repository, dict) or set(repository) != {"remote", "commit", "tree_digest"}:
        _schema_error("repository binding is invalid")
    if not isinstance(repository["remote"], str) or not repository["remote"].startswith("https://"):
        _schema_error("repository remote must be HTTPS")
    if not isinstance(repository["commit"], str) or not COMMIT_RE.fullmatch(repository["commit"]):
        _schema_error("repository commit is invalid")
    if not isinstance(repository["tree_digest"], str) or not SHA256_RE.fullmatch(repository["tree_digest"]):
        _schema_error("repository tree digest is invalid")

    steps = value["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        _schema_error("steps must contain 1 to 64 entries")
    step_ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    for step in steps:
        if not isinstance(step, dict) or set(step) != STEP_REQUIRED:
            _schema_error("step properties do not match v1")
        step_id = step["id"]
        if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
            _schema_error("step id is invalid")
        if step_id in step_ids:
            _schema_error("step ids must be unique")
        step_ids.append(step_id)
        if step["runner"] not in RUNNERS:
            _schema_error("runner is invalid")
        command = step["command"]
        if not isinstance(command, list) or not command or not all(
            isinstance(item, str) and item and "\x00" not in item and len(item) <= 4096
            for item in command
        ):
            _schema_error("command must be a non-empty argument vector")
        if not _is_relative_path(step["cwd"]):
            _schema_error("cwd must be a safe relative path")
        for field in ("inputs", "outputs"):
            paths = step[field]
            if not isinstance(paths, list) or len(paths) != len(set(paths)) or not all(
                _is_relative_path(path) for path in paths
            ):
                _schema_error(f"{field} must contain unique safe relative paths")
        depends_on = step["depends_on"]
        if not isinstance(depends_on, list) or len(depends_on) != len(set(depends_on)) or not all(
            isinstance(item, str) and ID_RE.fullmatch(item) for item in depends_on
        ):
            _schema_error("depends_on is invalid")
        dependencies[step_id] = depends_on
        timeout = step["timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
            _schema_error("timeout_seconds is invalid")
        exit_codes = step["expected_exit_codes"]
        if not isinstance(exit_codes, list) or not exit_codes or len(exit_codes) != len(set(exit_codes)):
            _schema_error("expected_exit_codes is invalid")
        if any(isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255 for code in exit_codes):
            _schema_error("expected_exit_codes must be integers from 0 through 255")
        if step["network"] != "none":
            _schema_error("step network must be none")
        capture = step["capture"]
        if not isinstance(capture, dict) or set(capture) != {"stdout", "stderr", "max_bytes"}:
            _schema_error("capture is invalid")
        if capture["stdout"] not in {"full", "hash", "none"} or capture["stderr"] not in {
            "full",
            "hash",
            "none",
        }:
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

    claim = value["claim"]
    if not isinstance(claim, dict) or set(claim) != {"id", "statement", "required_steps"}:
        _schema_error("claim is invalid")
    if not isinstance(claim["id"], str) or not ID_RE.fullmatch(claim["id"]):
        _schema_error("claim id is invalid")
    if not isinstance(claim["statement"], str) or not claim["statement"]:
        _schema_error("claim statement is invalid")
    required_steps = claim["required_steps"]
    if not isinstance(required_steps, list) or not required_steps or not set(required_steps) <= known:
        _schema_error("claim required_steps must reference declared steps")


def canonical_bytes(value: Any) -> bytes:
    # Contract fixtures use only ASCII object names. Production U02 must implement
    # RFC 8785 UTF-16 property ordering for the general admitted value domain.
    for item in _walk(value):
        if isinstance(item, dict) and any(not key.isascii() for key in item):
            raise ContractError("IS_CONTRACT_FIXTURE", "fixture object names must be ASCII")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def _resolve_schema_ref(
    reference: str,
    current_name: str,
    documents: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    document_ref, separator, fragment = reference.partition("#")
    target_name = Path(document_ref).name if document_ref else current_name
    if target_name not in documents:
        raise ContractError("IS_SCHEMA_DOCUMENT", f"unresolved schema document: {reference}")
    target: Any = documents[target_name]
    if separator and fragment:
        if not fragment.startswith("/"):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"unsupported schema fragment: {reference}")
        for token in fragment[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or token not in target:
                raise ContractError("IS_SCHEMA_DOCUMENT", f"unresolved schema pointer: {reference}")
            target = target[token]
    if not isinstance(target, dict):
        raise ContractError("IS_SCHEMA_DOCUMENT", f"schema reference is not an object: {reference}")
    return target, target_name


SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "maximum",
    "maxItems",
    "maxLength",
    "minimum",
    "minItems",
    "minLength",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


def _lint_schema_node(
    schema: dict[str, Any],
    current_name: str,
    documents: dict[str, dict[str, Any]],
    location: str,
) -> None:
    unknown = set(schema) - SCHEMA_KEYWORDS
    if unknown:
        raise ContractError(
            "IS_SCHEMA_DOCUMENT",
            f"{current_name}{location} uses unsupported or misspelled keywords: {sorted(unknown)}",
        )
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference:
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} has invalid $ref")
        _resolve_schema_ref(reference, current_name, documents)
    expected_type = schema.get("type")
    if expected_type is not None and expected_type not in {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }:
        raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} has invalid type")
    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, dict) or not all(isinstance(item, dict) for item in properties.values()):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} properties are invalid")
        for name, child in properties.items():
            _lint_schema_node(child, current_name, documents, f"{location}/properties/{name}")
    required = schema.get("required")
    if required is not None:
        if (
            not isinstance(required, list)
            or not all(isinstance(item, str) for item in required)
            or len(required) != len(set(required))
        ):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} required is invalid")
        if properties is not None and not set(required) <= set(properties):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} requires undeclared properties")
    definitions = schema.get("$defs")
    if definitions is not None:
        if not isinstance(definitions, dict) or not all(isinstance(item, dict) for item in definitions.values()):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} $defs are invalid")
        for name, child in definitions.items():
            _lint_schema_node(child, current_name, documents, f"{location}/$defs/{name}")
    alternatives = schema.get("oneOf")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not alternatives or not all(
            isinstance(item, dict) for item in alternatives
        ):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} oneOf is invalid")
        for index, child in enumerate(alternatives):
            _lint_schema_node(child, current_name, documents, f"{location}/oneOf/{index}")
    items = schema.get("items")
    if items is not None:
        if not isinstance(items, dict):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} items is invalid")
        _lint_schema_node(items, current_name, documents, f"{location}/items")
    additional = schema.get("additionalProperties")
    if additional is not None and not isinstance(additional, (bool, dict)):
        raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} additionalProperties is invalid")
    if isinstance(additional, dict):
        _lint_schema_node(additional, current_name, documents, f"{location}/additionalProperties")
    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} pattern is invalid")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ContractError(
                "IS_SCHEMA_DOCUMENT", f"{current_name}{location} pattern does not compile: {error}"
            ) from error
    enum = schema.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} enum is invalid")
    for keyword in ("minimum", "maximum", "minItems", "maxItems", "minLength", "maxLength"):
        if keyword in schema and (isinstance(schema[keyword], bool) or not isinstance(schema[keyword], int)):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} {keyword} is invalid")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise ContractError("IS_SCHEMA_DOCUMENT", f"{current_name}{location} uniqueItems is invalid")


def _schema_instance_error(location: str, message: str) -> None:
    raise ContractError("IS_SCHEMA_INSTANCE", f"{location}: {message}")


def validate_schema_instance(
    schema: dict[str, Any],
    value: Any,
    current_name: str,
    documents: dict[str, dict[str, Any]],
    location: str = "$",
) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        target, target_name = _resolve_schema_ref(reference, current_name, documents)
        validate_schema_instance(target, value, target_name, documents, location)

    expected_type = schema.get("type")
    if expected_type is not None and not _json_type_matches(value, expected_type):
        _schema_instance_error(location, f"expected {expected_type}")
    if "const" in schema and not _json_equal(value, schema["const"]):
        _schema_instance_error(location, "does not equal const")
    if "enum" in schema and not any(_json_equal(value, candidate) for candidate in schema["enum"]):
        _schema_instance_error(location, "is not in enum")

    alternatives = schema.get("oneOf")
    if alternatives is not None:
        matches = 0
        for alternative in alternatives:
            try:
                validate_schema_instance(alternative, value, current_name, documents, location)
                matches += 1
            except ContractError as error:
                if error.code != "IS_SCHEMA_INSTANCE":
                    raise
        if matches != 1:
            _schema_instance_error(location, f"matched {matches} oneOf alternatives")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            _schema_instance_error(location, f"missing required properties {missing}")
        for name, item in value.items():
            if name in properties:
                validate_schema_instance(properties[name], item, current_name, documents, f"{location}/{name}")
            else:
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    _schema_instance_error(location, f"unexpected property {name}")
                if isinstance(additional, dict):
                    validate_schema_instance(additional, item, current_name, documents, f"{location}/{name}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            _schema_instance_error(location, "has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            _schema_instance_error(location, "has too many items")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(_json_equal(item, earlier) for earlier in value[:index]):
                    _schema_instance_error(location, "contains duplicate items")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                validate_schema_instance(items, item, current_name, documents, f"{location}/{index}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            _schema_instance_error(location, "is shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            _schema_instance_error(location, "is longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            _schema_instance_error(location, "does not match pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            _schema_instance_error(location, "is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            _schema_instance_error(location, "is above maximum")


def load_schema_documents() -> dict[str, dict[str, Any]]:
    return {path.name: strict_load(path) for path in sorted(SCHEMAS.glob("*.schema.json"))}


def validate_schema_documents(documents: dict[str, dict[str, Any]]) -> list[str]:
    checked: list[str] = []
    for name, document in documents.items():
        if not isinstance(document, dict):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{name} is not an object")
        if document.get("$schema") != SCHEMA_DIALECT:
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{name} dialect is not Draft 2020-12")
        if not isinstance(document.get("$id"), str) or not document["$id"].startswith(
            "https://raw.githubusercontent.com/drwbkr1/incidentseal/main/schemas/"
        ):
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{name} has no stable repository-controlled $id")
        if document.get("type") != "object" or document.get("additionalProperties") is not False:
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{name} top-level object is not closed")
        if not isinstance(document.get("required"), list) or not document["required"]:
            raise ContractError("IS_SCHEMA_DOCUMENT", f"{name} has no required properties")
        _lint_schema_node(document, name, documents, "#")
        checked.append(name)
    if len(checked) != 4:
        raise ContractError("IS_SCHEMA_DOCUMENT", "expected exactly four v1 schema documents")
    return checked


def expect_error(path: Path, expected_code: str, *, validate: bool = True) -> None:
    try:
        value = strict_load(path)
        if validate:
            validate_manifest(value)
    except ContractError as error:
        if error.code != expected_code:
            raise ContractError(
                "IS_CONTRACT_FIXTURE",
                f"{path.name} returned {error.code}, expected {expected_code}",
            ) from error
        return
    raise ContractError("IS_CONTRACT_FIXTURE", f"{path.name} unexpectedly passed")


def main() -> int:
    try:
        schema_documents = load_schema_documents()
        schemas = validate_schema_documents(schema_documents)
        minimal = strict_load(FIXTURES / "workflow.valid.minimal.json")
        reordered = strict_load(FIXTURES / "workflow.valid.reordered.json")
        workflow_schema = schema_documents["workflow-manifest-v1.schema.json"]
        validate_schema_instance(
            workflow_schema,
            minimal,
            "workflow-manifest-v1.schema.json",
            schema_documents,
        )
        validate_schema_instance(
            workflow_schema,
            reordered,
            "workflow-manifest-v1.schema.json",
            schema_documents,
        )
        validate_manifest(minimal)
        validate_manifest(reordered)
        if minimal != reordered:
            raise ContractError("IS_CONTRACT_FIXTURE", "reordered fixture changed manifest meaning")

        canonical = canonical_bytes(minimal)
        expected_file = (FIXTURES / "workflow.valid.canonical.json").read_bytes()
        if expected_file.endswith(b"\n"):
            expected_file = expected_file[:-1]
        if canonical != expected_file:
            raise ContractError("IS_CONTRACT_FIXTURE", "canonical fixture bytes differ")
        digest = hashlib.sha256(canonical).hexdigest()

        vectors = strict_load(FIXTURES / "canonicalization-vectors.json")
        expected_digest = vectors["vectors"][0]["sha256"]
        if digest != expected_digest:
            raise ContractError("IS_CONTRACT_FIXTURE", "golden digest differs")

        expect_error(
            FIXTURES / "workflow.invalid.duplicate-key.json",
            "IS_MANIFEST_DUPLICATE_KEY",
            validate=False,
        )
        expect_error(
            FIXTURES / "workflow.invalid.float.json",
            "IS_MANIFEST_NUMBER_DOMAIN",
            validate=False,
        )
        invalid_network = strict_load(FIXTURES / "workflow.invalid.network.json")
        try:
            validate_schema_instance(
                workflow_schema,
                invalid_network,
                "workflow-manifest-v1.schema.json",
                schema_documents,
            )
        except ContractError as error:
            if error.code != "IS_SCHEMA_INSTANCE":
                raise
        else:
            raise ContractError("IS_CONTRACT_FIXTURE", "network mutation passed the workflow schema")
        expect_error(FIXTURES / "workflow.invalid.network.json", "IS_MANIFEST_SCHEMA")

        approval = strict_load(FIXTURES / "approval.valid.json")
        envelope = strict_load(FIXTURES / "cli-envelope.valid.json")
        event = strict_load(FIXTURES / "run-event.valid.json")
        validate_schema_instance(
            schema_documents["manifest-approval-v1.schema.json"],
            approval,
            "manifest-approval-v1.schema.json",
            schema_documents,
        )
        validate_schema_instance(
            schema_documents["cli-envelope-v1.schema.json"],
            envelope,
            "cli-envelope-v1.schema.json",
            schema_documents,
        )
        validate_schema_instance(
            schema_documents["run-event-v1.schema.json"],
            event,
            "run-event-v1.schema.json",
            schema_documents,
        )
        bound_digest = f"sha256:{digest}"
        if approval.get("manifest_digest") != bound_digest:
            raise ContractError("IS_CONTRACT_FIXTURE", "approval fixture digest is not bound")
        if envelope.get("policy", {}).get("manifest_digest") != bound_digest:
            raise ContractError("IS_CONTRACT_FIXTURE", "CLI fixture digest is not bound")
        if event.get("manifest_digest") != bound_digest or event.get("verdict") != "FAIL":
            raise ContractError("IS_CONTRACT_FIXTURE", "event fixture lost digest or verdict")
        if event.get("lifecycle") != "completed":
            raise ContractError("IS_CONTRACT_FIXTURE", "event fixture collapsed lifecycle")

        result = {
            "schema_version": "incidentseal-machine-contract-validation/v1",
            "status": "PASS",
            "schemas": schemas,
            "schema_subset_lint": "PASS",
            "schema_bound_fixtures": 5,
            "valid_workflows": 2,
            "invalid_workflows": 3,
            "golden_sha256": digest,
            "approval_binding": "PASS",
            "verdict_lifecycle_separation": "PASS",
            "third_party_dependencies": 0,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, KeyError, OSError, TypeError) as error:
        code = error.code if isinstance(error, ContractError) else "IS_CONTRACT_VALIDATOR"
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-machine-contract-validation/v1",
                    "status": "FAIL",
                    "error": {"code": code, "message": str(error)},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
