#!/usr/bin/env python3
"""Run recovery meta-validation through the existing exact source gate."""

from __future__ import annotations

import argparse
import hashlib
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


def copy_and_verify(artifact: dict[str, str], source: Path, destination: Path) -> dict:
    source_file = source / artifact["filename"]
    payload = source_file.read_bytes()
    observed = hashlib.sha256(payload).hexdigest()
    require(observed == artifact["sha256"], f"retained wheel hash mismatch: {artifact['filename']}")
    (destination / artifact["filename"]).write_bytes(payload)
    return {"filename":artifact["filename"],"sha256":observed,"bytes":len(payload),"source":"retained-exact-custody"}


def run(root: Path, wheel_dir: Path | None = None) -> dict:
    assessment_id, artifacts = source_artifacts(root)
    receipts = []
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-meta-") as temporary:
        temporary_path = Path(temporary).resolve()
        wheels = temporary_path / "wheels"
        site = temporary_path / "site"
        wheels.mkdir()
        site.mkdir()
        for artifact in artifacts:
            if wheel_dir is None:
                receipts.append(download_and_verify(artifact, wheels))
            else:
                receipts.append(copy_and_verify(artifact, wheel_dir, wheels))
        for artifact in artifacts:
            extract_wheel_safely(wheels / artifact["filename"], site)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(site)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-S", str(root / "scripts" / "validate_recovery_schema_meta.py"), "--root", str(root)],
            cwd=root,
            env=environment,
            capture_output=True,
            timeout=60,
            check=False,
        )
        require(completed.returncode == 0, f"recovery meta-validator exited {completed.returncode}: {completed.stdout.decode('utf-8', errors='replace')}")
        require(completed.stderr == b"", "recovery meta-validator wrote stderr")
        result = json.loads(completed.stdout)
        require(result.get("verification_verdict") == "PASS", "recovery meta-validator did not pass")
    require(temporary_path is not None and not temporary_path.exists(), "recovery meta-validation custody remained")
    result.update(
        {
            "source_gate_assessment_id":assessment_id,
            "artifact_count":len(receipts),
            "artifact_hashes_verified":True,
            "artifact_receipts":receipts,
            "temporary_install":True,
            "temporary_custody_removed":True,
            "network_used_for_acquisition":wheel_dir is None,
            "retained_exact_wheel_custody_used":wheel_dir is not None,
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--wheel-dir", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.root.resolve(), args.wheel_dir.resolve() if args.wheel_dir else None)
    except Exception as error:
        print(json.dumps({"schema_version":"incidentseal-recovery-meta-validation/v1","verification_verdict":"INVALID","error":f"{type(error).__name__}: {error}"}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
