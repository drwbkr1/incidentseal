#!/usr/bin/env python3
"""Require every unsafe integrated implementation mutation to fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    old: str
    new: str
    refresh_lock: bool = True


SURFACE = "src/incidentseal/integrated_recovery_surface.py"
CLI = "src/incidentseal/cli.py"
RUNNER = "scripts/run_integrated_recovery_implementation.py"
MUTATIONS = (
    Mutation("single-repetition", SURFACE, "REPETITIONS = 2", "REPETITIONS = 1"),
    Mutation("stage-dispatch-reordered", SURFACE, '("reliability-probe", lambda: _child_stage("reliability-probe", _reliability_semantic)),', '("journal-probe", lambda: _child_stage("reliability-probe", _reliability_semantic)),'),
    Mutation("child-platform-mode-drift", SURFACE, '"reliability-probe": ("topology", "reliability-probe", "--mode", "platform-validation", "--json")', '"reliability-probe": ("topology", "reliability-probe", "--mode", "workflow", "--json")'),
    Mutation("receipt-materialize-command-drift", SURFACE, '"receipt", "materialize", "--receipt", str(RECEIPT_PATH)', '"receipt", "verify", "--receipt", str(RECEIPT_PATH)'),
    Mutation("runner-argument-gate-removed", RUNNER, "if arguments:", "if False:"),
    Mutation("runner-command-identity-drift", RUNNER, 'COMMAND = "validation.integrated-recovery"', 'COMMAND = "workflow.execute"'),
    Mutation("arbitrary-integrated-command-exposed", CLI, "COMMANDS = {", 'COMMANDS = {\n    ("integrated", "run"): "integrated.run",'),
    Mutation("workflow-executor-exposed", CLI, "COMMANDS = {", 'COMMANDS = {\n    ("workflow", "execute"): "workflow.execute",'),
    Mutation("repository-custody-allowed", SURFACE, "ROOT in candidate.parents", "False"),
    Mutation("onedrive-custody-allowed", SURFACE, 'part.casefold() == "onedrive"', "False"),
    Mutation("docker-environment-shadow-allowed", SURFACE, 'key.upper() in {"DOCKER_HOST", "DOCKER_CONTEXT"}', "False"),
    Mutation("container-boundary-bypassed", SURFACE, "if containers or networks or incidentseal_volumes != protected or set(snapshot) != protected:", "if networks or incidentseal_volumes != protected or set(snapshot) != protected:"),
    Mutation("network-boundary-bypassed", SURFACE, "if containers or networks or incidentseal_volumes != protected or set(snapshot) != protected:", "if containers or incidentseal_volumes != protected or set(snapshot) != protected:"),
    Mutation("extra-volume-boundary-bypassed", SURFACE, "incidentseal_volumes != protected", "False"),
    Mutation("protected-snapshot-boundary-bypassed", SURFACE, "set(snapshot) != protected", "False"),
    Mutation("pre-stage-boundary-removed", SURFACE, "before = _boundary(docker, protected)", "before = root_boundary"),
    Mutation("post-stage-boundary-removed", SURFACE, "after = _boundary(docker, protected)", "after = root_boundary"),
    Mutation("stage-unchanged-check-bypassed", SURFACE, 'unchanged = before == after and after["protected_volume_identity"] == root_identity', "unchanged = True"),
    Mutation("completed-fail-collapsed", SURFACE, '_case("reliability-completed-fail", lifecycle="completed", run_verdict="FAIL", observation_verdict="FAIL", exit_code=10', '_case("reliability-completed-fail", lifecycle="failed", run_verdict=None, observation_verdict="FAIL", exit_code=21'),
    Mutation("invalid-input-gains-lifecycle", SURFACE, '_case("reliability-malformed-input", lifecycle=None, run_verdict=None, observation_verdict="INVALID", exit_code=12', '_case("reliability-malformed-input", lifecycle="completed", run_verdict=None, observation_verdict="INVALID", exit_code=12'),
    Mutation("cancelled-collapsed-to-failed", SURFACE, '_case("reliability-host-cancelled", lifecycle="cancelled", run_verdict=None, observation_verdict=None, exit_code=20', '_case("reliability-host-cancelled", lifecycle="failed", run_verdict=None, observation_verdict=None, exit_code=21'),
    Mutation("ambiguous-recovery-promoted", SURFACE, '_case("recovery-ambiguous-effects", lifecycle="running", run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11', '_case("recovery-ambiguous-effects", lifecycle="completed", run_verdict="PASS", observation_verdict="PASS", exit_code=0'),
    Mutation("conflicting-recovery-promoted", SURFACE, '_case("recovery-conflicting-effects", lifecycle="running", run_verdict=None, observation_verdict="FAIL", exit_code=21', '_case("recovery-conflicting-effects", lifecycle="completed", run_verdict="PASS", observation_verdict="PASS", exit_code=0'),
    Mutation("image-comparison-bypassed", SURFACE, '"same_exact_images": image_sets[0] == image_sets[1]', '"same_exact_images": True'),
    Mutation("contract-comparison-bypassed", SURFACE, '"same_contract_digest": contract_sets[0] == contract_sets[1] and len(set(contract_sets[0] + contract_sets[1])) == 1', '"same_contract_digest": True'),
    Mutation("receipt-comparison-bypassed", SURFACE, '"same_semantic_receipts": by_cycle[0]["receipt-state-matrix"]["semantic"] == by_cycle[1]["receipt-state-matrix"]["semantic"]', '"same_semantic_receipts": True'),
    Mutation("journal-comparison-bypassed", SURFACE, '"same_journal_streams": by_cycle[0]["journal-probe"]["semantic"]["streams"] == by_cycle[1]["journal-probe"]["semantic"]["streams"]', '"same_journal_streams": True'),
    Mutation("recovery-comparison-bypassed", SURFACE, '"same_recovery_decisions": by_cycle[0]["recovery-probe"]["semantic"]["decisions"] == by_cycle[1]["recovery-probe"]["semantic"]["decisions"]', '"same_recovery_decisions": True'),
    Mutation("normalized-toc-comparison-bypassed", SURFACE, '"same_normalized_toc": by_cycle[0]["backup-restore-probe"]["semantic"]["normalized_toc_digest"] == by_cycle[1]["backup-restore-probe"]["semantic"]["normalized_toc_digest"]', '"same_normalized_toc": True'),
    Mutation("restored-state-comparison-bypassed", SURFACE, '"same_restored_state": by_cycle[0]["backup-restore-probe"]["semantic"]["restored_state"] == by_cycle[1]["backup-restore-probe"]["semantic"]["restored_state"]', '"same_restored_state": True'),
    Mutation("negative-privilege-comparison-bypassed", SURFACE, '"same_negative_privileges": by_cycle[0]["backup-restore-probe"]["semantic"]["negative_privileges"] == by_cycle[1]["backup-restore-probe"]["semantic"]["negative_privileges"]', '"same_negative_privileges": True'),
    Mutation("protected-volume-comparison-bypassed", SURFACE, '"protected_volumes_unchanged": all(cycle["protected_volume_identity"] == root_identity for cycle in cycles)', '"protected_volumes_unchanged": True'),
    Mutation("interstage-teardown-comparison-bypassed", SURFACE, '"teardown_between_stages": all(stage["custody"]["unchanged"] for cycle in cycles for stage in cycle["stages"])', '"teardown_between_stages": True'),
    Mutation("cycle-teardown-comparison-bypassed", SURFACE, '"teardown_after_cycle": all(cycle["teardown_complete"] for cycle in cycles)', '"teardown_after_cycle": True'),
    Mutation("raw-archive-forced-equal", SURFACE, "if any(not str(item.get(\"archive_digest\", \"\")).startswith(\"sha256:\")", "if raw_archives[0] != raw_archives[1] or any(not str(item.get(\"archive_digest\", \"\")).startswith(\"sha256:\")"),
    Mutation("product-fail-reclassified-invalid", SURFACE, '"verdict": "FAIL"', '"verdict": "INVALID"'),
    Mutation("approval-access-claimed", SURFACE, '"approval_accessed": False', '"approval_accessed": True'),
    Mutation("workflow-execution-claimed", SURFACE, '"workflow_executed": False', '"workflow_executed": True'),
    Mutation("implementation-lock-digest-tampered", "requirements/integrated-recovery-implementation.lock.json", '"sha256": "sha256:', '"sha256": "sha256:0', refresh_lock=False),
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_lock(root: Path, changed_path: str) -> None:
    path = root / "requirements" / "integrated-recovery-implementation.lock.json"
    lock = json.loads(path.read_text(encoding="utf-8"))
    matched = False
    for entry in lock["files"]:
        if entry["path"] == changed_path:
            entry["sha256"] = digest(root / changed_path)
            matched = True
    if not matched:
        raise RuntimeError(f"mutation path is not locked: {changed_path}")
    path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    manifest = json.loads((ROOT / "fixtures/integrated-recovery/implementation-mutations.json").read_text(encoding="utf-8"))
    if [item["id"] for item in manifest["mutations"]] != [item.id for item in MUTATIONS]:
        raise RuntimeError("integrated implementation mutation manifest differs")
    results = []
    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="incidentseal-integrated-implementation-mutation-") as temporary:
            candidate = Path(temporary) / "repo"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            path = candidate / mutation.path
            text = path.read_text(encoding="utf-8")
            if mutation.old not in text:
                raise RuntimeError(f"mutation anchor is absent: {mutation.id}")
            path.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8")
            if mutation.refresh_lock:
                refresh_lock(candidate, mutation.path)
            completed = subprocess.run(
                [sys.executable, "-B", str(candidate / "scripts/validate_integrated_recovery_implementation.py"), "--root", str(candidate)],
                cwd=candidate, text=True, encoding="utf-8", capture_output=True, timeout=120, check=False,
            )
            try:
                value = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"mutation validator output is invalid: {mutation.id}") from error
            passed = completed.returncode == 1 and value.get("verification_verdict") == "INVALID" and not completed.stderr
            results.append({"id": mutation.id, "verification_verdict": "PASS" if passed else "FAIL"})
            if not passed:
                raise RuntimeError(f"unsafe mutation was not rejected: {mutation.id}: {completed.stdout}{completed.stderr}")
    print(json.dumps({
        "schema_version":"incidentseal-integrated-recovery-implementation-mutation-results/v1",
        "verification_verdict":"PASS",
        "mutation_count":len(results),
        "mutations":results,
        "runtime_started":False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
