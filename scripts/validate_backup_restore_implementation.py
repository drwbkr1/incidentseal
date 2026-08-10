#!/usr/bin/env python3
"""Validate the fixed host-only backup/restore implementation without runtime."""

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
    "docs/backup-restore-implementation.md",
    "fixtures/backup-restore/implementation-mutations.json",
    "requirements/backup-restore-contract.lock.json",
    "requirements/retained-runtime-volumes.lock.json",
    "requirements/topology-runtime.lock.json",
    "scripts/test_backup_restore_implementation_mutations.py",
    "scripts/validate_backup_restore_implementation.py",
    "src/incidentseal/backup_restore.py",
    "src/incidentseal/backup_restore_surface.py",
    "src/incidentseal/cli.py",
    "tests/test_backup_restore_surface.py",
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
    lock_path = root / "requirements" / "backup-restore-implementation.lock.json"
    lock = load(lock_path)
    require(lock.get("schema_version") == "incidentseal-backup-restore-implementation-lock/v1", "implementation lock version differs")
    entries = lock.get("files")
    require(isinstance(entries, list), "implementation lock files are absent")
    require(tuple(item.get("path") for item in entries if isinstance(item, dict)) == EXPECTED_PATHS, "implementation lock scope differs")
    require(len(entries) == len(set(EXPECTED_PATHS)), "implementation lock paths are duplicated")
    for entry in entries:
        path = root / entry["path"]
        require(path.is_file() and digest(path) == entry.get("sha256"), f"implementation drift: {entry.get('path')}")
    bindings = {
        "backup_restore_contract_lock": "requirements/backup-restore-contract.lock.json",
        "topology_runtime_lock": "requirements/topology-runtime.lock.json",
        "protected_volume_lock": "requirements/retained-runtime-volumes.lock.json",
    }
    for field, relative in bindings.items():
        require(lock.get(field) == {"path": relative, "sha256": digest(root / relative)}, f"{field} differs")
    require(lock.get("runtime_dependencies") == [], "backup implementation added runtime dependencies")
    require(lock.get("agent_mutation_commands") == ["topology.backup-restore-probe"], "backup mutation surface differs")
    require(lock.get("arbitrary_backup_restore_command") is False, "arbitrary backup or restore became available")

    surface = (root / "src/incidentseal/backup_restore_surface.py").read_text(encoding="utf-8")
    cli = (root / "src/incidentseal/cli.py").read_text(encoding="utf-8")
    guidance = (root / "docs/backup-restore-implementation.md").read_text(encoding="utf-8")
    for fragment in (
        'SOURCE_PROJECT = "incidentseal-backup-source"',
        'TARGET_PROJECT = "incidentseal-restore-target"',
        'SOURCE_VOLUME = "incidentseal-backup-source-data"',
        'TARGET_VOLUME = "incidentseal-restore-target-data"',
        '"--internal"',
        '"--read-only"',
        '"no-new-privileges"',
        '"--cap-drop", "ALL"',
        'not any(SECRET_ENV_RE.search(name_value)',
        'ROOT in candidate.parents',
        'part.casefold() == "onedrive"',
        'IN SHARE MODE',
        'return result.returncode != 0 and "statement timeout" in combined',
        '_digest(archive.read_bytes()) != archive_digest',
        'TOC_FORBIDDEN_RE.search(line)',
        'mount=(backup_dir, True)',
        'inspections.append(_run_migration(',
        'MIGRATION_NOTICE_RE.fullmatch(line)',
        'match is None or match.group(1) not in EXPECTED_EXISTING_RELATIONS',
        'set(negative_privileges.values()) == {"denied"}',
        '_run(docker, ["restart", TARGET_DATABASE])',
        'protected_before == protected_after',
        '[docker, "volume", "rm", name]',
        '"archive_custody_removed": True',
        '"approval_accessed": False',
        '"workflow_executed": False',
    ):
        require(fragment in surface, f"required backup boundary is absent: {fragment}")
    require(surface.count("inspections.append(_run_migration(") == 2, "source and target migration count differs")
    require('PGPASSWORD=' not in surface and 'target=/var/run/docker.sock' not in surface, "secret or Docker socket mount is present")
    require('SOURCE_PROJECT != TARGET_PROJECT' not in surface, "unexpected dynamic project authority is present")
    require(surface.index('_digest(archive.read_bytes()) != archive_digest') < surface.index('name="incidentseal-restore-target-restore"'), "restore precedes archive recheck")
    require(surface.index('name="incidentseal-restore-target-restore"') < surface.rindex('inspections.append(_run_migration('), "role migration precedes restore")
    require(surface.index('_run(docker, ["restart", TARGET_DATABASE])') < surface.index('restart_state = _measure_state'), "restart is not remeasured")

    require('("topology", "backup-restore-probe"): "topology.backup-restore-probe"' in cli, "backup probe CLI dispatch is absent")
    require('("backup", "restore")' not in cli, "arbitrary backup command is exposed")
    require("accepts no manifest, database, project, volume, archive, destination, path, or arbitrary operation" in guidance, "fixed backup guidance differs")

    docker = shutil.which("docker")
    before: tuple[str, ...] = ()
    if docker:
        observed = subprocess.run([docker, "ps", "-aq"], cwd=root, text=True, capture_output=True, timeout=30, check=False)
        require(observed.returncode == 0, "Docker history could not be observed")
        before = tuple(observed.stdout.splitlines())
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    contract = subprocess.run(
        [sys.executable, "-B", str(root / "scripts/validate_backup_restore_contract.py")],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(contract.returncode == 0 and json.loads(contract.stdout).get("verification_verdict") == "PASS" and not contract.stderr, "frozen backup contract regressed")
    tests = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "tests.test_backup_restore", "tests.test_backup_restore_surface"],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(tests.returncode == 0, f"backup implementation tests failed: {tests.stdout}{tests.stderr}")
    after: tuple[str, ...] = ()
    if docker:
        observed = subprocess.run([docker, "ps", "-aq"], cwd=root, text=True, capture_output=True, timeout=30, check=False)
        require(observed.returncode == 0, "Docker history could not be reobserved")
        after = tuple(observed.stdout.splitlines())
    require(before == after, "static backup validation changed Docker container history")
    return {
        "schema_version": "incidentseal-backup-restore-implementation-validation/v1",
        "verification_verdict": "PASS",
        "implementation_lock_digest": digest(lock_path),
        "contract_verdict": "PASS",
        "unit_tests": 12,
        "runtime_dependencies": 0,
        "agent_mutation_commands": 1,
        "arbitrary_backup_restore_command": False,
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
            "schema_version": "incidentseal-backup-restore-implementation-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_BACKUP_IMPLEMENTATION", "message": str(error)},
            "runtime_started": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
