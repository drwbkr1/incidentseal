#!/usr/bin/env python3
"""Validate the locked real receipt CLI without Docker, database, network, or approval state."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "receipt-implementation.lock.json"
EXPECTED_PATHS = (
    "docs/cli-contract.md",
    "docs/receipt-implementation.md",
    "incidentseal",
    "incidentseal.cmd",
    "requirements/receipt-contract.lock.json",
    "scripts/test_receipt_implementation_mutations.py",
    "scripts/validate_receipt_implementation.py",
    "src/incidentseal/__main__.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/manifest.py",
    "src/incidentseal/receipt.py",
    "tests/test_receipt.py",
)
EXPECTED_RUNTIME_FILES = (
    "incidentseal",
    "incidentseal.cmd",
    "src/incidentseal/__main__.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/manifest.py",
    "src/incidentseal/receipt.py",
)
EXPECTED_RECEIPT = "sha256:7293ac4087873338dfbe78411c74c809efd18b2ffac0aa88e052df33d0353c77"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run_cli(*arguments: str, root: Path = ROOT) -> tuple[int, dict[str, Any], str]:
    if os.name == "nt":
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(root / "incidentseal.cmd")]
    else:
        command = [str(root / "incidentseal")]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command + list(arguments),
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    if completed.stderr or completed.stdout.count("\n") != 1 or not completed.stdout.endswith("\n"):
        raise RuntimeError("real receipt CLI stream discipline failed")
    envelope = json.loads(completed.stdout)
    if envelope["process_exit_code"] != completed.returncode:
        raise RuntimeError("real receipt CLI process exit differs from envelope")
    return completed.returncode, envelope, completed.stderr


def expect(
    result: tuple[int, dict[str, Any], str],
    *,
    code: int,
    verdict: str,
    label: str,
    error: str | None = None,
) -> dict[str, Any]:
    actual_code, envelope, stderr = result
    errors = envelope.get("errors") or envelope.get("data", {}).get("errors") or []
    actual_error = errors[0].get("code") if errors else None
    if actual_code != code or envelope.get("verdict") != verdict or stderr or (error and actual_error != error):
        raise RuntimeError(f"{label} differed: code={actual_code}; verdict={envelope.get('verdict')}; error={actual_error}")
    return envelope


def snapshot(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def write_case(path: Path, value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(encoded + b"\n")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def docker_history() -> tuple[bool, tuple[str, ...]]:
    executable = shutil.which("docker")
    if executable is None:
        return False, ()
    completed = subprocess.run(
        [executable, "ps", "-aq"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Docker history observation failed")
    return True, tuple(completed.stdout.splitlines())


def copy_runtime_root(destination: Path) -> None:
    shutil.copytree(
        ROOT / "src" / "incidentseal",
        destination / "src" / "incidentseal",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for relative in ("incidentseal", "incidentseal.cmd", "requirements/receipt-implementation.lock.json"):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def validate_runtime_self_binding(temporary: Path, receipt: Path, bundle: Path) -> None:
    probe = temporary / "runtime-drift-probe"
    copy_runtime_root(probe)
    drifted = probe / "src" / "incidentseal" / "cli.py"
    drifted.write_bytes(drifted.read_bytes() + b"\n# receipt runtime drift probe\n")
    expected = {
        "code": 12,
        "verdict": "INVALID",
        "label": "runtime-drift verify",
        "error": "IS_RECEIPT_IMPLEMENTATION",
    }
    expect(
        run_cli(
            "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
            "--expected-digest", EXPECTED_RECEIPT, "--json", root=probe,
        ),
        **expected,
    )
    drift_output = temporary / "runtime-drift-output"
    expect(
        run_cli(
            "receipt", "materialize", "--receipt", str(ROOT / "fixtures/receipts/receipt.valid.json"),
            "--source-root", str(ROOT / "fixtures/receipts"),
            "--output-root", str(drift_output), "--json", root=probe,
        ),
        **{**expected, "label": "runtime-drift materialize"},
    )
    if drift_output.exists():
        raise RuntimeError("runtime-drift materialization wrote custody before rejection")


def validate() -> dict[str, Any]:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if lock.get("schema_version") != "incidentseal-receipt-implementation-lock/v1":
        raise RuntimeError("receipt implementation lock version differs")
    entries = lock.get("files", [])
    paths = [entry.get("path") for entry in entries]
    if tuple(sorted(paths)) != EXPECTED_PATHS or len(paths) != len(set(paths)):
        raise RuntimeError("receipt implementation lock path set differs")
    if tuple(lock.get("runtime_files", ())) != EXPECTED_RUNTIME_FILES:
        raise RuntimeError("receipt implementation runtime file set differs")
    for entry in entries:
        if digest(ROOT / entry["path"]) != entry["sha256"]:
            raise RuntimeError(f"receipt implementation lock drift: {entry['path']}")

    approval = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "IncidentSeal" / "approvals" / "v1"
    if approval.exists():
        raise RuntimeError("validation requires missing real approval state")
    docker_observed, docker_before = docker_history()
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-implementation-") as temporary_name:
        temporary = Path(temporary_name)
        temporary_path = temporary
        output = temporary / "output"
        write = expect(
            run_cli(
                "receipt", "materialize", "--receipt", str(ROOT / "fixtures/receipts/receipt.valid.json"),
                "--source-root", str(ROOT / "fixtures/receipts"), "--output-root", str(output), "--json",
            ),
            code=0,
            verdict="PASS",
            label="real receipt materialization",
        )
        if write["data"]["receipt_digest"] != EXPECTED_RECEIPT or not write["data"]["created"] or write["data"]["idempotent"]:
            raise RuntimeError("first materialization identity or creation state differed")
        bundle = Path(write["data"]["bundle_path"])
        repeat = expect(
            run_cli(
                "receipt", "materialize", "--receipt", str(ROOT / "fixtures/receipts/receipt.valid.json"),
                "--source-root", str(ROOT / "fixtures/receipts"), "--output-root", str(output), "--json",
            ),
            code=0,
            verdict="PASS",
            label="idempotent receipt materialization",
        )
        if repeat["data"]["created"] or not repeat["data"]["idempotent"] or Path(repeat["data"]["bundle_path"]) != bundle:
            raise RuntimeError("repeat materialization was not exact and idempotent")
        if list(output.rglob("*.tmp")):
            raise RuntimeError("materialization left staging custody")

        receipt = bundle / "receipt.json"
        exact_before = snapshot(bundle)
        exact = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED_RECEIPT, "--json",
            ),
            code=0,
            verdict="PASS",
            label="exact receipt verification",
        )
        if exact_before != snapshot(bundle):
            raise RuntimeError("exact receipt verification changed bundle bytes")

        unbound = expect(
            run_cli("receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle), "--json"),
            code=11,
            verdict="INCONCLUSIVE",
            label="unbound receipt verification",
            error="IS_RECEIPT_IDENTITY_UNBOUND",
        )
        if exact_before != snapshot(bundle):
            raise RuntimeError("unbound receipt verification changed bundle bytes")

        mismatch = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", "sha256:" + "0" * 64, "--json",
            ),
            code=12,
            verdict="INVALID",
            label="mismatched receipt verification",
            error="IS_RECEIPT_IDENTITY_MISMATCH",
        )
        if exact_before != snapshot(bundle):
            raise RuntimeError("mismatched receipt verification changed bundle bytes")

        artifact = bundle / "artifacts" / "result.json"
        original_artifact = artifact.read_bytes()
        artifact.write_bytes(b'{"status":"FAIL"}\n')
        corrupt_before = snapshot(bundle)
        corrupt = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED_RECEIPT, "--json",
            ),
            code=10,
            verdict="FAIL",
            label="corrupt artifact verification",
            error="IS_RECEIPT_ARTIFACT_MISMATCH",
        )
        if corrupt_before != snapshot(bundle):
            raise RuntimeError("corrupt artifact verification changed bundle bytes")
        artifact.write_bytes(original_artifact)
        artifact.unlink()
        missing_before = snapshot(bundle)
        missing = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED_RECEIPT, "--json",
            ),
            code=11,
            verdict="INCONCLUSIVE",
            label="missing artifact verification",
            error="IS_RECEIPT_ARTIFACT_MISSING",
        )
        if missing_before != snapshot(bundle):
            raise RuntimeError("missing artifact verification changed bundle bytes")
        artifact.write_bytes(original_artifact)

        source_case = temporary / "corrupt-source"
        shutil.copytree(ROOT / "fixtures" / "receipts", source_case)
        (source_case / "artifacts" / "result.json").write_bytes(b'{"status":"FAIL"}\n')
        source_output = temporary / "corrupt-source-output"
        expect(
            run_cli(
                "receipt", "materialize", "--receipt", str(source_case / "receipt.valid.json"),
                "--source-root", str(source_case), "--output-root", str(source_output), "--json",
            ),
            code=12,
            verdict="INVALID",
            label="corrupt source materialization",
            error="IS_RECEIPT_ARTIFACT",
        )
        if source_output.exists():
            raise RuntimeError("corrupt source materialization created output custody")

        forbidden = ROOT / ".incidentseal-receipt-forbidden-validation"
        if forbidden.exists():
            raise RuntimeError("repository output denial probe path already exists")
        denied = expect(
            run_cli(
                "receipt", "materialize", "--receipt", str(ROOT / "fixtures/receipts/receipt.valid.json"),
                "--source-root", str(ROOT / "fixtures/receipts"), "--output-root", str(forbidden), "--json",
            ),
            code=12,
            verdict="INVALID",
            label="repository output denial",
            error="IS_RECEIPT_CUSTODY",
        )
        if forbidden.exists():
            raise RuntimeError("repository output denial created repository custody")

        valid_document = json.loads(receipt.read_text(encoding="utf-8"))
        event_case = json.loads(json.dumps(valid_document))
        event_case["event_chain"]["links"][0]["event_digest"] = "sha256:" + "0" * 64
        event_path = temporary / "receipt.invalid-event-digest.json"
        event_expected = write_case(event_path, event_case)
        event_invalid = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(event_path), "--bundle-root", str(bundle),
                "--expected-digest", event_expected, "--json",
            ),
            code=12,
            verdict="INVALID",
            label="stored event digest mutation",
            error="IS_RECEIPT_EVENT_DIGEST",
        )

        summary_case = json.loads(json.dumps(valid_document))
        summary_case["run"]["lifecycle"] = "failed"
        summary_path = temporary / "receipt.invalid-summary.json"
        summary_expected = write_case(summary_path, summary_case)
        summary_invalid = expect(
            run_cli(
                "receipt", "verify", "--receipt", str(summary_path), "--bundle-root", str(bundle),
                "--expected-digest", summary_expected, "--json",
            ),
            code=12,
            verdict="INVALID",
            label="run summary mutation",
            error="IS_RECEIPT_STATE",
        )

        validate_runtime_self_binding(temporary, receipt, bundle)
        bundle_files = sorted(snapshot(bundle))

    if temporary_path is None or temporary_path.exists():
        raise RuntimeError("temporary receipt custody was not removed")
    if approval.exists():
        raise RuntimeError("receipt validation changed approval state")
    docker_after_observed, docker_after = docker_history()
    if docker_after_observed != docker_observed or docker_after != docker_before:
        raise RuntimeError("receipt validation changed Docker container history")
    return {
        "schema_version": "incidentseal-receipt-implementation-validation/v1",
        "verdict": "PASS",
        "implementation_lock_digest": digest(LOCK),
        "receipt_digest": EXPECTED_RECEIPT,
        "materialize_invocation_id": write["invocation_id"],
        "idempotent_invocation_id": repeat["invocation_id"],
        "verify_invocation_id": exact["invocation_id"],
        "unbound_invocation_id": unbound["invocation_id"],
        "mismatch_invocation_id": mismatch["invocation_id"],
        "corrupt_invocation_id": corrupt["invocation_id"],
        "missing_invocation_id": missing["invocation_id"],
        "denied_invocation_id": denied["invocation_id"],
        "event_invalid_invocation_id": event_invalid["invocation_id"],
        "summary_invalid_invocation_id": summary_invalid["invocation_id"],
        "temporary_custody_removed": True,
        "bundle_files": bundle_files,
        "runtime_dependency_count": 0,
        "runtime_self_binding": "PASS",
        "docker_history_observed": docker_observed,
        "docker_history_unchanged": True,
        "docker_started": False,
        "database_accessed": False,
        "network_accessed": False,
        "approval_accessed": False,
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-receipt-implementation-validation/v1",
                    "verdict": "INVALID",
                    "error": {"code": "IS_RECEIPT_IMPLEMENTATION", "message": str(error)},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
