#!/usr/bin/env python3
"""Full Draft 2020-12 meta-schema and bound-fixture validation.

This script intentionally depends on the evaluation-only lock in
requirements/meta-validation.lock. It must be run from an isolated temporary
target after the source gate and exact wheel hashes have been verified.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema.validators import validator_for
from referencing import Registry, Resource


SCHEMA_FILES = (
    "workflow-manifest-v1.schema.json",
    "manifest-approval-v1.schema.json",
    "cli-envelope-v1.schema.json",
    "run-event-v1.schema.json",
    "portable-receipt-v1.schema.json",
    "receipt-verification-v1.schema.json",
)

VALID_FIXTURES = (
    ("workflow-manifest-v1.schema.json", "contracts/workflow.valid.minimal.json"),
    ("workflow-manifest-v1.schema.json", "contracts/workflow.valid.reordered.json"),
    ("workflow-manifest-v1.schema.json", "contracts/workflow.valid.canonical.json"),
    ("manifest-approval-v1.schema.json", "contracts/approval.valid.json"),
    ("cli-envelope-v1.schema.json", "contracts/cli-envelope.valid.json"),
    ("run-event-v1.schema.json", "contracts/run-event.valid.json"),
    ("portable-receipt-v1.schema.json", "receipts/receipt.valid.json"),
    ("receipt-verification-v1.schema.json", "receipts/verification.valid.json"),
)

INVALID_FIXTURES = (
    ("workflow-manifest-v1.schema.json", "contracts/workflow.invalid.float.json"),
    ("workflow-manifest-v1.schema.json", "contracts/workflow.invalid.network.json"),
    ("portable-receipt-v1.schema.json", "receipts/receipt.invalid.minimal.json"),
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def first_error(validator: Any, instance: Any) -> str | None:
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if not errors:
        return None
    error = errors[0]
    location = "/".join(str(part) for part in error.absolute_path) or "$"
    return f"{location}: {error.message}"


def validate(root: Path) -> dict[str, Any]:
    schemas_dir = root / "schemas"
    fixtures_dir = root / "fixtures"
    schemas = {name: load_json(schemas_dir / name) for name in SCHEMA_FILES}

    resources = []
    for name, schema in schemas.items():
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError(f"{name} has no non-empty $id")
        resources.append((schema_id, Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)

    schema_checks: list[dict[str, str]] = []
    validators: dict[str, Any] = {}
    for name, schema in schemas.items():
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        validators[name] = validator_type(schema, registry=registry)
        schema_checks.append(
            {
                "schema": name,
                "declared_dialect": schema["$schema"],
                "validator": validator_type.__name__,
                "status": "PASS",
            }
        )

    fixture_checks: list[dict[str, Any]] = []
    for schema_name, fixture_name in VALID_FIXTURES:
        error = first_error(validators[schema_name], load_json(fixtures_dir / fixture_name))
        if error is not None:
            raise ValueError(f"valid fixture {fixture_name} was rejected: {error}")
        fixture_checks.append(
            {"schema": schema_name, "fixture": fixture_name, "expected": "valid", "status": "PASS"}
        )

    for schema_name, fixture_name in INVALID_FIXTURES:
        error = first_error(validators[schema_name], load_json(fixtures_dir / fixture_name))
        if error is None:
            raise ValueError(f"invalid fixture {fixture_name} was accepted")
        fixture_checks.append(
            {
                "schema": schema_name,
                "fixture": fixture_name,
                "expected": "invalid",
                "observed_error": error,
                "status": "PASS",
            }
        )

    packages = {
        name: importlib.metadata.version(name)
        for name in (
            "attrs",
            "jsonschema",
            "jsonschema-specifications",
            "referencing",
            "rpds-py",
            "typing-extensions",
        )
    }
    return {
        "schema_version": "incidentseal-json-schema-meta-validation/v1",
        "status": "PASS",
        "observed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "draft": "https://json-schema.org/draft/2020-12/schema",
        "schema_count": len(schema_checks),
        "fixture_count": len(fixture_checks),
        "schema_checks": schema_checks,
        "fixture_checks": fixture_checks,
        "packages": packages,
        "network_used_during_validation": False,
        "runtime_dependency": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        report = validate(args.root.resolve())
    except Exception as exc:  # fail closed with one machine-readable result
        report = {
            "schema_version": "incidentseal-json-schema-meta-validation/v1",
            "status": "FAIL",
            "observed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
