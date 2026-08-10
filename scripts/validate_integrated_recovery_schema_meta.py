#!/usr/bin/env python3
"""Validate the integrated recovery schema and fixtures with full Draft 2020-12."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    schema = json.loads((root / "schemas" / "integrated-recovery-matrix-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid = json.loads((root / "fixtures" / "integrated-recovery" / "matrix.valid.json").read_text(encoding="utf-8"))
    invalid = json.loads((root / "fixtures" / "integrated-recovery" / "matrix.invalid.minimal.json").read_text(encoding="utf-8"))
    validator.validate(valid)
    if not list(validator.iter_errors(invalid)):
        raise RuntimeError("minimal invalid matrix unexpectedly validates")
    print(json.dumps({"schema_version":"incidentseal-integrated-recovery-meta-validation/v1","verification_verdict":"PASS","draft":"https://json-schema.org/draft/2020-12/schema","schema_count":1,"fixture_count":2,"runtime_dependency":False,"network_used_during_validation":False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
