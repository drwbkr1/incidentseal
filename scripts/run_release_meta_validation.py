#!/usr/bin/env python3
"""Run release-plan meta-validation through the existing exact source gate."""

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

from scripts.run_recovery_meta_validation import copy_and_verify  # noqa: E402
from scripts.run_meta_validation import download_and_verify, extract_wheel_safely, source_artifacts  # noqa: E402


def run(root: Path, wheel_dir: Path | None) -> dict[str, object]:
    assessment_id, artifacts = source_artifacts(root)
    receipts: list[dict[str, object]] = []
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-release-meta-") as temporary:
        temporary_path = Path(temporary).resolve()
        wheels = temporary_path / "wheels"
        site = temporary_path / "site"
        wheels.mkdir()
        site.mkdir()
        for artifact in artifacts:
            receipts.append(download_and_verify(artifact, wheels) if wheel_dir is None else copy_and_verify(artifact, wheel_dir, wheels))
        for artifact in artifacts:
            extract_wheel_safely(wheels / artifact["filename"], site)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(site)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-S", str(root / "scripts" / "validate_release_schema_meta.py"), "--root", str(root)],
            cwd=root, env=environment, capture_output=True, timeout=60, check=False,
        )
        if completed.returncode != 0 or completed.stderr:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"release meta-validator failed: {detail}")
        result = json.loads(completed.stdout)
    if temporary_path is None or temporary_path.exists():
        raise RuntimeError("release meta-validation custody remained")
    result.update({
        "source_gate_assessment_id": assessment_id,
        "artifact_count": len(receipts),
        "artifact_hashes_verified": True,
        "network_used_for_acquisition": wheel_dir is None,
        "retained_exact_wheel_custody_used": wheel_dir is not None,
        "temporary_custody_removed": True,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--wheel-dir", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.root.resolve(), args.wheel_dir.resolve() if args.wheel_dir else None)
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-release-meta-validation/v1",
            "verification_verdict": "INVALID",
            "error": f"{type(error).__name__}: {error}",
        }, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
