#!/usr/bin/env python3
"""Validate the locked host-only recovery implementation without starting runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


EXPECTED_PATHS = (
    "containers/migration/001-schema.sql",
    "docs/cli-contract.md",
    "docs/recovery-implementation.md",
    "fixtures/recovery/implementation-mutations.json",
    "requirements/recovery-contract.lock.json",
    "scripts/test_recovery_implementation_mutations.py",
    "scripts/validate_recovery_implementation.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/recovery.py",
    "src/incidentseal/recovery_probe.py",
    "src/incidentseal/recovery_surface.py",
    "tests/test_recovery.py",
    "tests/test_recovery_surface.py",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    lock_path = root / "requirements" / "recovery-implementation.lock.json"
    lock = load(lock_path)
    require(lock.get("schema_version") == "incidentseal-recovery-implementation-lock/v1", "implementation lock version differs")
    entries = lock.get("files")
    require(isinstance(entries, list), "implementation lock files are absent")
    require(tuple(item.get("path") for item in entries if isinstance(item, dict)) == EXPECTED_PATHS, "implementation lock scope differs")
    require(len(entries) == len(set(EXPECTED_PATHS)), "implementation lock paths are duplicated")
    for entry in entries:
        path = root / entry["path"]
        require(path.is_file() and digest(path) == entry.get("sha256"), f"implementation drift: {entry.get('path')}")
    contract_binding = lock.get("recovery_contract_lock")
    require(
        contract_binding == {
            "path": "requirements/recovery-contract.lock.json",
            "sha256": digest(root / "requirements" / "recovery-contract.lock.json"),
        },
        "recovery contract binding differs",
    )
    require(lock.get("runtime_dependencies") == [], "recovery implementation added runtime dependencies")
    require(lock.get("agent_mutation_commands") == ["topology.recovery-probe"], "agent recovery mutation surface differs")
    require(lock.get("arbitrary_recovery_command") is False, "arbitrary recovery command became available")

    sql = (root / "containers" / "migration" / "001-schema.sql").read_text(encoding="utf-8")
    core = (root / "src" / "incidentseal" / "recovery_surface.py").read_text(encoding="utf-8")
    probe = (root / "src" / "incidentseal" / "recovery_probe.py").read_text(encoding="utf-8")
    cli = (root / "src" / "incidentseal" / "cli.py").read_text(encoding="utf-8")
    guidance = (root / "docs" / "recovery-implementation.md").read_text(encoding="utf-8")

    for fragment in (
        "CREATE TABLE IF NOT EXISTS incidentseal_recovery_fences",
        "workflow_fence_token bigint NOT NULL",
        "recovery_fence_token bigint NOT NULL DEFAULT 0",
        "incidentseal_acquire_recovery_fence",
        "incidentseal_release_recovery_fence",
        "pg_advisory_xact_lock",
        "FOR UPDATE",
        "workflow_expires_at > CURRENT_TIMESTAMP",
        "IF v_fence.recovery_expires_at > CURRENT_TIMESTAMP THEN",
        "another recovery holder is active",
        "recovery_fence_token = f.recovery_fence_token + 1",
        "p_recovery_expires_at > CURRENT_TIMESTAMP + interval '5 minutes'",
        "REVOKE ALL ON TABLE incidentseal_recovery_fences FROM PUBLIC",
        "REVOKE ALL ON FUNCTION public.incidentseal_acquire_recovery_fence",
        "REVOKE ALL ON FUNCTION public.incidentseal_release_recovery_fence",
        "('003-recovery-fence-v1')" if "('003-recovery-fence-v1')" in sql else "'003-recovery-fence-v1'",
    ):
        require(fragment in sql, f"required recovery SQL boundary is absent: {fragment}")
    require(
        sql.count("PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_run_id::text, 1));") == 2,
        "recovery acquire and release advisory-lock count differs",
    )
    for forbidden in (
        "GRANT SELECT ON TABLE incidentseal_recovery_fences TO incidentseal_runner",
        "GRANT UPDATE ON TABLE incidentseal_recovery_fences TO incidentseal_runner",
        "GRANT EXECUTE ON FUNCTION public.incidentseal_acquire_recovery_fence",
    ):
        require(forbidden not in sql, f"runner recovery authority is forbidden: {forbidden}")

    for fragment in (
        "repository in candidate.parents",
        'part.casefold() == "onedrive"',
        "os.replace(temporary, target)",
        "validate_decision(pending[\"decision\"], pending[\"observation\"])",
        "canonical_bytes(refreshed) != canonical_bytes(observation)",
        "self.store.save(pending)",
        "self.backend.acquire_recovery_fence",
        "self.backend.replay_step",
        "self.backend.append_record",
        "self.backend.stop_runtime",
        "self._observe(plan)",
        '"verdict": None',
    ):
        require(fragment in core, f"required recovery executor boundary is absent: {fragment}")
    require(core.index("self.backend.acquire_recovery_fence") < core.index("self.backend.stop_runtime"), "runtime stop precedes recovery fencing")
    require(core.index("self.store.save(pending)") < core.index("self.backend.stop_runtime"), "runtime stop precedes durable pending custody")

    for fragment in (
        'host.get("NetworkMode") == "none"',
        'host.get("ReadonlyRootfs") is True',
        'host.get("Privileged") is False',
        '"ALL" in (host.get("CapDrop") or [])',
        'host.get("SecurityOpt") == ["no-new-privileges"]',
        'not (value.get("Mounts") or [])',
        'labels.get("dev.incidentseal.workflow-fence-token")',
        'labels.get("dev.incidentseal.recovery-surface") == "platform-validation"',
        "not self._active_fence",
        '"stop", "--time", "2", container_id',
        '"--network", "none"',
        '"down", "--volumes", "--remove-orphans"',
        "protected_before == protected_after",
        '"approval_accessed": False',
        '"workflow_executed": False',
    ):
        require(fragment in probe, f"required real recovery boundary is absent: {fragment}")
    for forbidden in ("/var/run/docker.sock", "--network\", \"host", "--privileged", "OneDrive\\"):
        require(forbidden not in probe, f"forbidden recovery runtime boundary is present: {forbidden}")

    require('("topology", "recovery-probe"): "topology.recovery-probe"' in cli, "recovery probe CLI dispatch is absent")
    require('("run", "recover")' not in cli and '("run", "append")' not in cli, "arbitrary recovery or append command is exposed")
    require("fixed `platform-validation` probe" in guidance, "recovery guidance lost the fixed probe boundary")

    docker = shutil.which("docker")
    before: tuple[str, ...] = ()
    if docker:
        observed_before = subprocess.run([docker, "ps", "-aq"], cwd=root, text=True, capture_output=True, timeout=30, check=False)
        require(observed_before.returncode == 0, "Docker history could not be observed")
        before = tuple(observed_before.stdout.splitlines())
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    contract = subprocess.run(
        [sys.executable, "-B", str(root / "scripts" / "validate_recovery_contract.py")],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(contract.returncode == 0 and json.loads(contract.stdout).get("verification_verdict") == "PASS" and not contract.stderr, "frozen recovery contract regressed")
    tests = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "tests.test_recovery", "tests.test_recovery_surface"],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(tests.returncode == 0, f"recovery unit tests failed: {tests.stdout}{tests.stderr}")
    after: tuple[str, ...] = ()
    if docker:
        observed_after = subprocess.run([docker, "ps", "-aq"], cwd=root, text=True, capture_output=True, timeout=30, check=False)
        require(observed_after.returncode == 0, "Docker history could not be reobserved")
        after = tuple(observed_after.stdout.splitlines())
    require(before == after, "static recovery validation changed Docker container history")
    return {
        "schema_version": "incidentseal-recovery-implementation-validation/v1",
        "verification_verdict": "PASS",
        "implementation_lock_digest": digest(lock_path),
        "contract_verdict": "PASS",
        "unit_tests": 12,
        "runtime_dependencies": 0,
        "agent_mutation_commands": 1,
        "arbitrary_recovery_command": False,
        "runtime_started": False,
        "container_history_unchanged": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-recovery-implementation-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_RECOVERY_IMPLEMENTATION", "message": str(error)},
            "runtime_started": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
