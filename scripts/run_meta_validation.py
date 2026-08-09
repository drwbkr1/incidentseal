#!/usr/bin/env python3
"""Acquire source-gated wheels, validate hashes, and run schema checks in temp custody."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


GATE_RELATIVE_PATH = Path("records/source-gates/2026-08-09-jsonschema-meta-validation.json")
LOCK_RELATIVE_PATH = Path("requirements/meta-validation.lock")
VALIDATOR_RELATIVE_PATH = Path("scripts/validate_json_schema_meta.py")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def source_artifacts(root: Path) -> tuple[str, list[dict[str, str]]]:
    gate = json.loads((root / GATE_RELATIVE_PATH).read_text(encoding="utf-8"))
    require(gate.get("contract_version") == "source-gate/v1", "unexpected source gate contract")
    require(gate.get("decision", {}).get("status") == "ready", "source gate is not ready")
    approved = set(gate["decision"].get("approved_actions", []))
    required_actions = {
        "download exact wheel artifacts",
        "verify exact wheel hashes",
        "install exact wheels into an isolated temporary directory",
        "execute full Draft 2020-12 schema meta-validation",
    }
    require(required_actions <= approved, "source gate does not authorize the evaluation sequence")

    lock_text = (root / LOCK_RELATIVE_PATH).read_text(encoding="utf-8")
    artifacts: list[dict[str, str]] = []
    for source in gate.get("sources", []):
        locator = source.get("locator", "")
        url, marker, expected = locator.partition("#sha256=")
        require(marker == "#sha256=" and len(expected) == 64, "source locator lacks exact SHA-256")
        filename = url.rsplit("/", 1)[-1]
        require(filename.endswith(".whl"), "source locator is not a wheel")
        require(f"sha256:{expected}" in lock_text, f"{filename} hash is absent from dependency lock")
        artifacts.append(
            {"source_id": source["source_id"], "url": url, "filename": filename, "sha256": expected}
        )
    require(len(artifacts) == 6, "source gate must bind exactly six evaluation artifacts")
    require(len({item["filename"] for item in artifacts}) == 6, "wheel filenames are not unique")
    return gate["assessment_id"], artifacts


def download_and_verify(artifact: dict[str, str], wheelhouse: Path) -> dict[str, Any]:
    destination = wheelhouse / artifact["filename"]
    digest = hashlib.sha256()
    request = urllib.request.Request(artifact["url"], headers={"User-Agent": "IncidentSeal-evaluator/0"})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            output.write(chunk)
    observed = digest.hexdigest()
    require(observed == artifact["sha256"], f"hash mismatch for {artifact['filename']}")
    return {"filename": artifact["filename"], "sha256": observed, "bytes": destination.stat().st_size}


def extract_wheel_safely(wheel: Path, target: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            name = member.filename
            relative = PurePosixPath(name)
            require(not relative.is_absolute(), f"absolute wheel member rejected: {name}")
            require(".." not in relative.parts and "\\" not in name, f"unsafe wheel member rejected: {name}")
            file_type = (member.external_attr >> 16) & 0o170000
            require(file_type != stat.S_IFLNK, f"wheel symlink rejected: {name}")
            destination = (target / Path(*relative.parts)).resolve()
            require(destination == target or target in destination.parents, f"wheel member escaped target: {name}")
        archive.extractall(target)


def run(root: Path) -> dict[str, Any]:
    assessment_id, artifacts = source_artifacts(root)
    temporary_path: Path | None = None
    child_report: dict[str, Any]
    artifact_receipts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-meta-") as temporary:
        temporary_path = Path(temporary).resolve()
        wheelhouse = temporary_path / "wheels"
        site = temporary_path / "site"
        wheelhouse.mkdir()
        site.mkdir()
        for artifact in artifacts:
            artifact_receipts.append(download_and_verify(artifact, wheelhouse))
        for artifact in artifacts:
            extract_wheel_safely(wheelhouse / artifact["filename"], site)

        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(site)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-S", str(root / VALIDATOR_RELATIVE_PATH), "--root", str(root)],
            cwd=root,
            env=environment,
            capture_output=True,
            check=False,
            timeout=60,
        )
        require(completed.returncode == 0, f"meta-validator exited {completed.returncode}")
        require(completed.stderr == b"", "meta-validator wrote stderr")
        child_report = json.loads(completed.stdout.decode("utf-8"))
        require(child_report.get("status") == "PASS", "meta-validator did not report PASS")

    require(temporary_path is not None and not temporary_path.exists(), "temporary custody was not removed")
    child_report.update(
        {
            "source_gate_assessment_id": assessment_id,
            "artifact_count": len(artifact_receipts),
            "artifact_hashes_verified": True,
            "artifact_receipts": artifact_receipts,
            "temporary_install": True,
            "temporary_custody_removed": True,
        }
    )
    return child_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = run(args.root.resolve())
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-json-schema-meta-validation/v1",
                    "status": "FAIL",
                    "error": f"{type(error).__name__}: {error}",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
