#!/usr/bin/env python3
"""Full Draft 2020-12 validation for the interruption-recovery schema set."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema.validators import validator_for
from referencing import Registry, Resource


SCHEMAS = ("recovery-observation-v1.schema.json", "recovery-decision-v1.schema.json")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def first_error(validator: Any, instance: Any) -> str | None:
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if not errors:
        return None
    error = errors[0]
    location = "/".join(str(part) for part in error.absolute_path) or "$"
    return f"{location}: {error.message}"


def validate(root: Path) -> dict[str, Any]:
    sys.path.insert(0, str(root / "src"))
    from incidentseal.recovery import decide_recovery  # noqa: E402

    schemas = {name: load(root / "schemas" / name) for name in SCHEMAS}
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()]
    )
    validators = {}
    schema_checks = []
    for name, schema in schemas.items():
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        validators[name] = validator_type(schema, registry=registry)
        schema_checks.append({"schema":name,"validator":validator_type.__name__,"status":"PASS"})
    fixture_checks = []
    vectors = load(root / "fixtures" / "recovery" / "vectors.json")
    for case in vectors["cases"]:
        observation = case["observation"]
        decision = decide_recovery(observation)
        for schema_name, instance, label in (
            ("recovery-observation-v1.schema.json", observation, f"{case['id']}:observation"),
            ("recovery-decision-v1.schema.json", decision, f"{case['id']}:decision"),
        ):
            error = first_error(validators[schema_name], instance)
            if error is not None:
                raise ValueError(f"valid fixture {label} was rejected: {error}")
            fixture_checks.append({"schema":schema_name,"fixture":label,"expected":"valid","status":"PASS"})
    for schema_name, fixture_name in (
        ("recovery-observation-v1.schema.json", "observation.invalid.minimal.json"),
        ("recovery-decision-v1.schema.json", "decision.invalid.minimal.json"),
    ):
        error = first_error(validators[schema_name], load(root / "fixtures" / "recovery" / fixture_name))
        if error is None:
            raise ValueError(f"invalid fixture {fixture_name} was accepted")
        fixture_checks.append({"schema":schema_name,"fixture":fixture_name,"expected":"invalid","observed_error":error,"status":"PASS"})
    packages = {
        name: importlib.metadata.version(name)
        for name in ("attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "typing-extensions")
    }
    return {
        "schema_version":"incidentseal-recovery-meta-validation/v1",
        "verification_verdict":"PASS",
        "draft":"https://json-schema.org/draft/2020-12/schema",
        "schema_count":len(schema_checks),
        "fixture_count":len(fixture_checks),
        "schema_checks":schema_checks,
        "fixture_checks":fixture_checks,
        "packages":packages,
        "network_used_during_validation":False,
        "runtime_dependency":False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = validate(args.root.resolve())
    except Exception as error:
        print(json.dumps({"schema_version":"incidentseal-recovery-meta-validation/v1","verification_verdict":"INVALID","error":f"{type(error).__name__}: {error}"}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
