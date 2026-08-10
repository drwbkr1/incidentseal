#!/usr/bin/env python3
"""Validate the fixed repeated integrated implementation without runtime."""

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
    "AGENTS.md",
    "docs/integrated-recovery-implementation.md",
    "fixtures/integrated-recovery/implementation-mutations.json",
    "requirements/backup-restore-implementation.lock.json",
    "requirements/event-journal-implementation.lock.json",
    "requirements/integrated-recovery-contract.lock.json",
    "requirements/receipt-implementation.lock.json",
    "requirements/recovery-implementation.lock.json",
    "requirements/retained-runtime-volumes.lock.json",
    "requirements/topology-implementation.lock.json",
    "requirements/topology-runtime.lock.json",
    "scripts/run_integrated_recovery_implementation.py",
    "scripts/test_integrated_recovery_implementation_mutations.py",
    "scripts/validate_integrated_recovery_implementation.py",
    "src/incidentseal/cli.py",
    "src/incidentseal/integrated_recovery_surface.py",
    "tests/test_integrated_recovery_surface.py",
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
    lock_path = root / "requirements" / "integrated-recovery-implementation.lock.json"
    lock = load(lock_path)
    require(lock.get("schema_version") == "incidentseal-integrated-recovery-implementation-lock/v1", "implementation lock version differs")
    entries = lock.get("files")
    require(isinstance(entries, list), "implementation lock files are absent")
    require(tuple(item.get("path") for item in entries if isinstance(item, dict)) == EXPECTED_PATHS, "implementation lock scope differs")
    require(len(entries) == len(set(EXPECTED_PATHS)), "implementation lock paths are duplicated")
    for entry in entries:
        path = root / entry["path"]
        require(path.is_file() and digest(path) == entry.get("sha256"), f"implementation drift: {entry.get('path')}")
    bindings = {
        "integrated_recovery_contract_lock": "requirements/integrated-recovery-contract.lock.json",
        "topology_implementation_lock": "requirements/topology-implementation.lock.json",
        "topology_runtime_lock": "requirements/topology-runtime.lock.json",
        "receipt_implementation_lock": "requirements/receipt-implementation.lock.json",
        "event_journal_implementation_lock": "requirements/event-journal-implementation.lock.json",
        "recovery_implementation_lock": "requirements/recovery-implementation.lock.json",
        "backup_restore_implementation_lock": "requirements/backup-restore-implementation.lock.json",
        "protected_volume_lock": "requirements/retained-runtime-volumes.lock.json",
    }
    for field, relative in bindings.items():
        require(lock.get(field) == {"path": relative, "sha256": digest(root / relative)}, f"{field} differs")
    require(lock.get("runtime_dependencies") == [], "integrated implementation added runtime dependencies")
    require(lock.get("agent_mutation_commands") == ["scripts/run_integrated_recovery_implementation.py"], "integrated mutation surface differs")
    require(lock.get("arbitrary_stage_arguments") is False, "arbitrary stage arguments became available")
    require(lock.get("workflow_executor") is False, "workflow execution became available")
    require(lock.get("repetitions") == 2, "integrated repetition count differs")
    require(lock.get("stage_order") == [
        "receipt-state-matrix", "reliability-probe", "journal-probe", "recovery-probe", "backup-restore-probe",
    ], "integrated stage order differs")
    require(lock.get("command_identities") == [
        "receipt.materialize", "receipt.verify", "topology.reliability-probe", "topology.journal-probe",
        "topology.recovery-probe", "topology.backup-restore-probe",
    ], "integrated command identities differ")
    require(lock.get("comparison_excludes") == [
        "archive_digest", "backup_id", "container_id", "created_at_utc", "invocation_id", "receipt_digest",
    ], "integrated comparison exclusions differ")

    surface = (root / "src/incidentseal/integrated_recovery_surface.py").read_text(encoding="utf-8")
    cli = (root / "src/incidentseal/cli.py").read_text(encoding="utf-8")
    runner = (root / "scripts/run_integrated_recovery_implementation.py").read_text(encoding="utf-8")
    guidance = (root / "docs/integrated-recovery-implementation.md").read_text(encoding="utf-8")
    for fragment in (
        "REPETITIONS = 2",
        '"reliability-probe": ("topology", "reliability-probe", "--mode", "platform-validation", "--json")',
        '"journal-probe": ("topology", "journal-probe", "--mode", "platform-validation", "--json")',
        '"recovery-probe": ("topology", "recovery-probe", "--mode", "platform-validation", "--json")',
        '"backup-restore-probe": ("topology", "backup-restore-probe", "--mode", "platform-validation", "--json")',
        '("receipt-state-matrix", _receipt_stage)',
        '("reliability-probe", lambda: _child_stage("reliability-probe", _reliability_semantic))',
        '("journal-probe", lambda: _child_stage("journal-probe", _journal_semantic))',
        '("recovery-probe", lambda: _child_stage("recovery-probe", _recovery_semantic))',
        '("backup-restore-probe", lambda: _child_stage("backup-restore-probe", _backup_semantic))',
        '"receipt", "materialize", "--receipt", str(RECEIPT_PATH)',
        'arguments = ["receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle)]',
        'part.casefold() == "onedrive"',
        "ROOT in candidate.parents",
        'key.upper() in {"DOCKER_HOST", "DOCKER_CONTEXT"}',
        "if containers or networks or incidentseal_volumes != protected or set(snapshot) != protected:",
        "incidentseal_volumes != protected",
        "before == after and after[\"protected_volume_identity\"] == root_identity",
        '_case("reliability-completed-fail", lifecycle="completed", run_verdict="FAIL", observation_verdict="FAIL", exit_code=10',
        '_case("reliability-malformed-input", lifecycle=None, run_verdict=None, observation_verdict="INVALID", exit_code=12',
        '_case("reliability-database-outage", lifecycle="failed", run_verdict=None, observation_verdict=None, exit_code=21',
        '_case("reliability-host-cancelled", lifecycle="cancelled", run_verdict=None, observation_verdict=None, exit_code=20',
        '_case("journal-stale", lifecycle="stale", run_verdict=None, observation_verdict=None, exit_code=22',
        '_case("journal-superseded", lifecycle="superseded", run_verdict=None, observation_verdict=None, exit_code=23',
        '_case("recovery-ambiguous-effects", lifecycle="running", run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11',
        '_case("recovery-conflicting-effects", lifecycle="running", run_verdict=None, observation_verdict="FAIL", exit_code=21',
        '"same_exact_images": image_sets[0] == image_sets[1]',
        '"same_contract_digest": contract_sets[0] == contract_sets[1]',
        '"same_semantic_receipts": by_cycle[0]["receipt-state-matrix"]["semantic"] == by_cycle[1]["receipt-state-matrix"]["semantic"]',
        '"same_journal_streams": by_cycle[0]["journal-probe"]["semantic"]["streams"] == by_cycle[1]["journal-probe"]["semantic"]["streams"]',
        '"same_recovery_decisions": by_cycle[0]["recovery-probe"]["semantic"]["decisions"] == by_cycle[1]["recovery-probe"]["semantic"]["decisions"]',
        '"same_normalized_toc": by_cycle[0]["backup-restore-probe"]["semantic"]["normalized_toc_digest"] == by_cycle[1]["backup-restore-probe"]["semantic"]["normalized_toc_digest"]',
        '"same_restored_state": by_cycle[0]["backup-restore-probe"]["semantic"]["restored_state"] == by_cycle[1]["backup-restore-probe"]["semantic"]["restored_state"]',
        '"same_negative_privileges": by_cycle[0]["backup-restore-probe"]["semantic"]["negative_privileges"] == by_cycle[1]["backup-restore-probe"]["semantic"]["negative_privileges"]',
        '"protected_volumes_unchanged": all(cycle["protected_volume_identity"] == root_identity for cycle in cycles)',
        '"teardown_between_stages": all(stage["custody"]["unchanged"] for cycle in cycles for stage in cycle["stages"])',
        '"teardown_after_cycle": all(cycle["teardown_complete"] for cycle in cycles)',
        '"raw_archive_receipts"',
        '"verdict": "FAIL"',
        '"approval_accessed": False',
        '"workflow_executed": False',
    ):
        require(fragment in surface, f"required integrated boundary is absent: {fragment}")
    require(surface.count("for repetition in range(1, REPETITIONS + 1)") == 1, "integrated cycle loop differs")
    require(surface.count("before = _boundary(docker, protected)") == 1, "integrated per-stage pre-boundary differs")
    require(surface.count("after = _boundary(docker, protected)") == 1, "integrated per-stage post-boundary differs")
    require('target=/var/run/docker.sock' not in surface and 'PGPASSWORD=' not in surface, "secret or Docker socket mount is present")
    require('"approval_accessed": True' not in surface, "integrated surface claims approval access")
    require('"workflow_executed": True' not in surface, "integrated surface claims workflow execution")
    require('raw_archives[0] != raw_archives[1]' not in surface and 'raw_archives[0] == raw_archives[1]' not in surface, "raw archives became a cross-cycle equality gate")
    require('("topology", "integrated-recovery-probe")' not in cli, "unapproved seventh CLI command is exposed")
    require('("integrated", "run")' not in cli and '("workflow", "execute")' not in cli, "arbitrary or workflow command is exposed")
    require('COMMAND = "validation.integrated-recovery"' in runner, "fixed integrated runner identity differs")
    require("if arguments:" in runner and '"IS_USAGE"' in runner, "integrated runner does not reject arguments")
    require("accepts no arguments: no manifest, workflow, project, volume, receipt, archive, source, destination, stage selection, repetition count, mode selection, or arbitrary operation" in guidance, "fixed integrated guidance differs")

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
        [sys.executable, "-B", str(root / "scripts/validate_integrated_recovery_contract.py")],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(contract.returncode == 0 and json.loads(contract.stdout).get("verification_verdict") == "PASS" and not contract.stderr, "frozen integrated contract regressed")
    tests = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "tests.test_integrated_recovery", "tests.test_integrated_recovery_surface"],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(tests.returncode == 0, f"integrated implementation tests failed: {tests.stdout}{tests.stderr}")
    after: tuple[str, ...] = ()
    if docker:
        observed = subprocess.run([docker, "ps", "-aq"], cwd=root, text=True, capture_output=True, timeout=30, check=False)
        require(observed.returncode == 0, "Docker history could not be reobserved")
        after = tuple(observed.stdout.splitlines())
    require(before == after, "static integrated validation changed Docker container history")
    return {
        "schema_version": "incidentseal-integrated-recovery-implementation-validation/v1",
        "verification_verdict": "PASS",
        "implementation_lock_digest": digest(lock_path),
        "contract_verdict": "PASS",
        "unit_tests": 15,
        "runtime_dependencies": 0,
        "agent_mutation_commands": 1,
        "arbitrary_stage_arguments": False,
        "workflow_executor": False,
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
            "schema_version": "incidentseal-integrated-recovery-implementation-validation/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_INTEGRATED_IMPLEMENTATION", "message": str(error)},
            "runtime_started": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
