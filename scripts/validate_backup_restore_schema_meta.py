#!/usr/bin/env python3
"""Validate the backup/restore schema and fixtures with Draft 2020-12."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    root = parser.parse_args().root.resolve()
    schema = json.loads((root / "schemas" / "backup-restore-receipt-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    vectors = json.loads((root / "fixtures" / "backup-restore" / "vectors.json").read_text(encoding="utf-8"))
    invalid = json.loads((root / "fixtures" / "backup-restore" / "receipt.invalid.minimal.json").read_text(encoding="utf-8"))
    valid_errors = list(validator.iter_errors(vectors["golden"]))
    invalid_errors = list(validator.iter_errors(invalid))
    if valid_errors or not invalid_errors:
        raise RuntimeError("backup/restore fixture schema expectations differ")
    print(json.dumps({"schema_version":"incidentseal-backup-restore-meta-validation/v1","verification_verdict":"PASS","draft":schema["$schema"],"schema_count":1,"fixture_count":2,"runtime_dependency":False,"network_used_during_validation":False}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
