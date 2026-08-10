#!/usr/bin/env python3
"""Validate dashboard schemas and fixtures with full Draft 2020-12."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


def checked(root: Path, schema_name: str, valid_name: str, invalid_name: str) -> None:
    schema = json.loads((root / "schemas" / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid = json.loads((root / "fixtures" / "dashboard" / valid_name).read_text(encoding="utf-8"))
    invalid = json.loads((root / "fixtures" / "dashboard" / invalid_name).read_text(encoding="utf-8"))
    validator.validate(valid)
    if not list(validator.iter_errors(invalid)):
        raise RuntimeError(f"minimal invalid dashboard fixture unexpectedly validates: {invalid_name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    checked(root, "dashboard-snapshot-v1.schema.json", "snapshot.valid.json", "snapshot.invalid.minimal.json")
    checked(root, "dashboard-scenario-corpus-v1.schema.json", "scenario-corpus.valid.json", "scenario-corpus.invalid.minimal.json")
    print(json.dumps({
        "schema_version": "incidentseal-dashboard-meta-validation/v1",
        "verification_verdict": "PASS",
        "draft": "https://json-schema.org/draft/2020-12/schema",
        "schema_count": 2,
        "fixture_count": 4,
        "runtime_dependency": False,
        "network_used_during_validation": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
