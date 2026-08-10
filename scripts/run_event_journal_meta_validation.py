#!/usr/bin/env python3
"""Run event journal meta-validation through the existing exact source gate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.run_meta_validation import download_and_verify, extract_wheel_safely, source_artifacts  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(root: Path) -> dict:
    assessment_id, artifacts = source_artifacts(root)
    receipts = []
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-journal-meta-") as temporary:
        temporary_path = Path(temporary).resolve()
        wheels = temporary_path / "wheels"
        site = temporary_path / "site"
        wheels.mkdir()
        site.mkdir()
        for artifact in artifacts:
            receipts.append(download_and_verify(artifact, wheels))
        for artifact in artifacts:
            extract_wheel_safely(wheels / artifact["filename"], site)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(site)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-S", str(root / "scripts" / "validate_event_journal_schema_meta.py"), "--root", str(root)],
            cwd=root,
            env=environment,
            capture_output=True,
            timeout=60,
            check=False,
        )
        require(completed.returncode == 0, f"event journal meta-validator exited {completed.returncode}")
        require(completed.stderr == b"", "event journal meta-validator wrote stderr")
        result = json.loads(completed.stdout)
        require(result.get("verdict") == "PASS", "event journal meta-validator did not pass")
    require(temporary_path is not None and not temporary_path.exists(), "event journal meta-validation custody remained")
    result.update(
        {
            "source_gate_assessment_id": assessment_id,
            "artifact_count": len(receipts),
            "artifact_hashes_verified": True,
            "artifact_receipts": receipts,
            "temporary_install": True,
            "temporary_custody_removed": True,
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        result = run(args.root.resolve())
    except Exception as error:
        print(json.dumps({"schema_version":"incidentseal-event-journal-meta-validation/v1","verdict":"INVALID","error":f"{type(error).__name__}: {error}"}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
