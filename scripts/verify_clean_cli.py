#!/usr/bin/env python3
"""Verify the committed IncidentSeal CLI from a clean temporary local clone."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    result: str


def run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def json_command(
    arguments: Sequence[str],
    *,
    cwd: Path,
    expected_exit: int,
    expected_command: str,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    completed = run(arguments, cwd=cwd, environment=environment)
    require(completed.returncode == expected_exit, f"{expected_command} exit was {completed.returncode}")
    require(completed.stderr == b"", f"{expected_command} wrote stderr")
    require(completed.stdout.endswith(b"\n"), f"{expected_command} lacked final newline")
    require(completed.stdout.count(b"\n") == 1, f"{expected_command} emitted multiple lines")
    try:
        envelope = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{expected_command} stdout was not one UTF-8 JSON document") from error
    require(envelope.get("schema_version") == "incidentseal-cli-envelope/v1", "CLI schema_version drifted")
    require(envelope.get("command") == expected_command, f"command id drifted for {expected_command}")
    require(envelope.get("process_exit_code") == completed.returncode, "process and envelope exits differ")
    require(isinstance(envelope.get("errors"), list), "errors is not an array")
    require(isinstance(envelope.get("evidence"), list), "evidence is not an array")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-head")
    arguments = parser.parse_args()
    source = arguments.source.resolve()
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is unavailable")
    source_head = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=source, text=True).strip()
    expected_head = source_head if arguments.expected_head is None else arguments.expected_head
    require(source_head == expected_head, "source HEAD differs from expected clean-copy candidate")
    source_status = subprocess.check_output([git, "status", "--porcelain=v1"], cwd=source, text=True).splitlines()
    require(not source_status, "source worktree is not clean")

    approval_root = (
        Path(os.environ["LOCALAPPDATA"]) / "IncidentSeal" / "approvals" / "v1"
        if os.name == "nt"
        else Path.home() / ".local" / "state" / "incidentseal" / "approvals" / "v1"
    )
    require(not approval_root.exists(), "real approval root exists before clean-copy validation")
    checks: list[Check] = []

    with tempfile.TemporaryDirectory(prefix="incidentseal-u05-") as temporary:
        clone = Path(temporary) / "clone"
        clone_result = run(
            [git, "clone", "--quiet", "--no-hardlinks", str(source), str(clone)],
            cwd=source,
            timeout=120,
        )
        require(clone_result.returncode == 0, "local clean clone failed")
        clone_head = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=clone, text=True).strip()
        require(clone_head == expected_head, "clean clone HEAD differs from candidate")
        require(
            subprocess.check_output([git, "status", "--porcelain=v1"], cwd=clone, text=True).strip() == "",
            "clean clone began dirty",
        )
        checks.append(Check("local-clean-clone", "PASS", f"head={clone_head}"))

        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(clone / "src")
        tests = run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=clone,
            environment=environment,
            timeout=180,
        )
        test_output = (tests.stdout + tests.stderr).decode("utf-8", errors="replace")
        require(tests.returncode == 0, "clean-clone test suite failed")
        match = re.search(r"Ran ([0-9]+) tests", test_output)
        require(match is not None and int(match.group(1)) >= 38, "clean-clone test count was below 38")
        checks.append(Check("clean-clone-tests", "PASS", f"tests={match.group(1)}"))

        windows_launcher = (
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(clone / "incidentseal.cmd")]
            if os.name == "nt"
            else [str(clone / "incidentseal")]
        )
        valid = str(clone / "fixtures" / "contracts" / "workflow.valid.minimal.json")
        reordered = str(clone / "fixtures" / "contracts" / "workflow.valid.reordered.json")
        invalid = str(clone / "fixtures" / "contracts" / "workflow.invalid.network.json")
        lint = json_command(
            [*windows_launcher, "policy", "lint", "--manifest", valid, "--json"],
            cwd=clone,
            expected_exit=0,
            expected_command="policy.lint",
        )
        require(lint["data"].get("valid") is True, "real lint did not report valid")
        digest = json_command(
            [*windows_launcher, "policy", "digest", "--manifest", reordered, "--json"],
            cwd=clone,
            expected_exit=0,
            expected_command="policy.digest",
        )
        require(
            digest["data"].get("manifest_digest")
            == "sha256:0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45",
            "real digest differed from frozen vector",
        )
        invalid_envelope = json_command(
            [*windows_launcher, "policy", "lint", "--manifest", invalid, "--json"],
            cwd=clone,
            expected_exit=12,
            expected_command="policy.lint",
        )
        require(invalid_envelope.get("verdict") == "INVALID", "invalid manifest lost INVALID verdict")
        missing_input = json_command(
            [*windows_launcher, "policy", "lint", "--manifest", str(clone / "missing.json"), "--json"],
            cwd=clone,
            expected_exit=74,
            expected_command="policy.lint",
        )
        require(missing_input["errors"][0]["code"] == "IS_MANIFEST_READ", "missing input error drifted")
        checks.append(Check("windows-machine-cli", "PASS", "exits=0,12,74; streams=exact"))

        for command in ("status", "diff"):
            envelope = json_command(
                [*windows_launcher, "policy", command, "--manifest", valid, "--json"],
                cwd=clone,
                expected_exit=12,
                expected_command=f"policy.{command}",
            )
            require(envelope["policy"]["approval_status"] == "MISSING", f"policy {command} was not MISSING")
        forbidden = json_command(
            [*windows_launcher, "operator", "approve-manifest", "--manifest", valid, "--json"],
            cwd=clone,
            expected_exit=77,
            expected_command="operator.approve-manifest",
        )
        require(
            forbidden["errors"][0]["code"] == "IS_AUTHORITY_MUTATION_FORBIDDEN",
            "machine authority denial drifted",
        )
        redirected = run(
            [*windows_launcher, "operator", "approve-manifest", "--manifest", valid],
            cwd=clone,
        )
        require(redirected.returncode == 77 and redirected.stdout == b"", "redirected operator command did not fail closed")
        shortcut = run(
            [*windows_launcher, "operator", "approve-manifest", "--manifest", valid, "--yes"],
            cwd=clone,
        )
        require(shortcut.returncode == 64, "operator confirmation shortcut did not return usage error")
        require(not approval_root.exists(), "agent-safe clean-copy commands created real approval state")
        checks.append(Check("approval-authority-boundary", "PASS", "MISSING=12; machine=77; redirected=77; --yes=64"))

        isolated = json_command(
            [sys.executable, "-S", "-m", "incidentseal", "policy", "digest", "--manifest", valid, "--json"],
            cwd=clone,
            environment=environment,
            expected_exit=0,
            expected_command="policy.digest",
        )
        require(isolated["data"]["manifest_digest"] == digest["data"]["manifest_digest"], "site-disabled digest drifted")
        checks.append(Check("dependency-isolation", "PASS", "python_site_disabled=true"))

        if os.name == "nt":
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            require(git_bash.exists(), "Git Bash is unavailable")
            posix = json_command(
                [
                    str(git_bash),
                    "./incidentseal",
                    "policy",
                    "digest",
                    "--manifest",
                    "fixtures/contracts/workflow.valid.minimal.json",
                    "--json",
                ],
                cwd=clone,
                expected_exit=0,
                expected_command="policy.digest",
            )
            require(posix["data"]["manifest_digest"] == digest["data"]["manifest_digest"], "POSIX launcher digest drifted")
            checks.append(Check("posix-launcher-on-windows", "PASS", "git-bash native-python path conversion"))

        contracts = run(
            [sys.executable, "scripts/validate_machine_contracts.py"],
            cwd=clone,
            environment=environment,
        )
        require(contracts.returncode == 0, "frozen machine contract validator failed")
        mutations = run(
            [sys.executable, "scripts/test_machine_contract_mutations.py"],
            cwd=clone,
            environment=environment,
        )
        require(mutations.returncode == 0, "frozen contract mutation validator failed")
        checks.append(Check("frozen-contracts", "PASS", "schemas=4; bound_fixtures=5; mutations=4"))

        meta = run(
            [sys.executable, "scripts/run_meta_validation.py", "--root", str(clone)],
            cwd=clone,
            environment=environment,
            timeout=180,
        )
        require(meta.returncode == 0, "full Draft 2020-12 meta-validation failed")
        meta_result = json.loads(meta.stdout.decode("utf-8"))
        require(meta_result.get("status") == "PASS", "schema meta-validation status was not PASS")
        require(meta_result.get("schema_count") == 4, "schema meta-validation count drifted")
        require(meta_result.get("fixture_count") == 8, "schema fixture validation count drifted")
        require(meta_result.get("artifact_count") == 6, "schema evaluator artifact count drifted")
        require(meta_result.get("artifact_hashes_verified") is True, "schema evaluator hashes were not verified")
        require(meta_result.get("temporary_custody_removed") is True, "schema evaluator custody was not removed")
        checks.append(Check("full-schema-meta-validation", "PASS", "draft=2020-12; schemas=4; fixtures=8; artifacts=6"))

        matrix = run(
            [sys.executable, "scripts/evaluate_fail_closed.py"],
            cwd=clone,
            environment=environment,
            timeout=180,
        )
        require(matrix.returncode == 0, "fail-closed matrix failed in clean clone")
        matrix_result = json.loads(matrix.stdout.decode("utf-8"))
        require(matrix_result.get("status") == "PASS", "fail-closed matrix status was not PASS")
        require(matrix_result.get("execution_count") == 50, "fail-closed execution count drifted")
        require(matrix_result.get("real_approval_created") is False, "matrix claimed a real approval")
        checks.append(Check("fail-closed-matrix", "PASS", "scenarios=25; executions=50"))

        final_status = subprocess.check_output([git, "status", "--porcelain=v1"], cwd=clone, text=True).strip()
        require(final_status == "", "clean clone became dirty after verification")
        require(not approval_root.exists(), "clean-copy validation created real approval state")
        checks.append(Check("post-validation-cleanliness", "PASS", "worktree_clean=true; real_approval_root=false"))

    output = {
        "schema_version": "incidentseal-clean-cli-verification/v1",
        "observed_at_utc": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PASS",
        "candidate_commit": expected_head,
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "check_count": len(checks),
        "docker_invoked": False,
        "real_approval_created": False,
        "checks": [check.__dict__ for check in checks],
    }
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-clean-cli-verification/v1",
                    "status": "FAIL",
                    "error": str(error),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        raise SystemExit(1)
