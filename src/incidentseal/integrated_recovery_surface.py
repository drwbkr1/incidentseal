"""Fixed host-owned repeated integrated receipt and recovery probe."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

from .integrated_recovery import (
    COMMANDS,
    COMPARISON_EXCLUDES,
    EXPECTED_CASES,
    STAGE_ORDER,
    validate_matrix,
)
from .journal_surface import _volume_snapshot
from .manifest import canonical_bytes, strict_load_bytes
from .reliability_surface import _load_retained_volume_lock, _volume_names
from .runtime import _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _sha256_file


IMPLEMENTATION_LOCK = ROOT / "requirements" / "integrated-recovery-implementation.lock.json"
MATRIX_PATH = ROOT / "fixtures" / "integrated-recovery" / "matrix.valid.json"
RECEIPT_PATH = ROOT / "fixtures" / "receipts" / "receipt.valid.json"
RECEIPT_SOURCE = ROOT / "fixtures" / "receipts"
REPETITIONS = 2
FIXED_STAGE_ARGUMENTS = {
    "reliability-probe": ("topology", "reliability-probe", "--mode", "platform-validation", "--json"),
    "journal-probe": ("topology", "journal-probe", "--mode", "platform-validation", "--json"),
    "recovery-probe": ("topology", "recovery-probe", "--mode", "platform-validation", "--json"),
    "backup-restore-probe": ("topology", "backup-restore-probe", "--mode", "platform-validation", "--json"),
}
EXPECTED_IMPLEMENTATION_PATHS = (
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
EXPECTED_CASE_MAP = {item[0]: item for item in EXPECTED_CASES}


class CompositeProductFailure(RuntimeError):
    """A valid child product FAIL that must not be reclassified as INVALID."""

    def __init__(self, stage: str, envelope: dict[str, Any], output_digest: str) -> None:
        super().__init__(f"{stage} returned product FAIL")
        self.stage = stage
        self.envelope = envelope
        self.output_digest = output_digest


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except (OSError, ValueError) as error:
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", f"integrated input is unreadable: {path.name}") from error


def validate_integrated_recovery_implementation_lock() -> str:
    """Require the complete composite implementation to match its exact local lock."""

    lock = _load(IMPLEMENTATION_LOCK)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-integrated-recovery-implementation-lock/v1":
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated implementation lock version differs")
    entries = lock.get("files")
    if not isinstance(entries, list) or tuple(item.get("path") for item in entries if isinstance(item, dict)) != EXPECTED_IMPLEMENTATION_PATHS:
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated implementation lock scope differs")
    for entry in entries:
        path = ROOT / str(entry.get("path", ""))
        try:
            observed = _digest(path.read_bytes())
        except OSError as error:
            raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", f"locked integrated file is unavailable: {path.name}") from error
        if observed != entry.get("sha256"):
            raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", f"integrated implementation drift: {entry.get('path')}")
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
        if lock.get(field) != {"path": relative, "sha256": _sha256_file(ROOT / relative)}:
            raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", f"integrated implementation {field} differs")
    if lock.get("runtime_dependencies") != []:
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated implementation added runtime dependencies")
    if lock.get("agent_mutation_commands") != ["scripts/run_integrated_recovery_implementation.py"]:
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated mutation surface differs")
    if lock.get("arbitrary_stage_arguments") is not False or lock.get("workflow_executor") is not False:
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated authority broadened")
    if lock.get("repetitions") != REPETITIONS or lock.get("stage_order") != list(STAGE_ORDER):
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated repetition or stage order differs")
    if lock.get("comparison_excludes") != list(COMPARISON_EXCLUDES):
        raise TopologyError("IS_INTEGRATED_IMPLEMENTATION", "integrated dynamic comparison exclusions differ")
    return _digest(IMPLEMENTATION_LOCK.read_bytes())


def _safe_temporary(path: Path) -> Path:
    candidate = path.resolve(strict=True)
    if candidate == ROOT or ROOT in candidate.parents or any(part.casefold() == "onedrive" for part in candidate.parts):
        raise TopologyError("IS_INTEGRATED_CUSTODY", "integrated temporary custody overlaps the repository or OneDrive")
    return candidate


def _tree_digest(root: Path) -> str:
    items = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        raw = path.read_bytes()
        items.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw), "digest": _digest(raw)})
    return _digest(canonical_bytes(items))


def _cli_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key.upper().startswith(("INCIDENTSEAL_", "COMPOSE_")) or key.upper() in {"DOCKER_HOST", "DOCKER_CONTEXT"}:
            environment.pop(key, None)
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _run_cli(arguments: tuple[str, ...], *, allowed_exits: set[int], timeout: int = 900) -> tuple[dict[str, Any], str]:
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "incidentseal", *arguments],
        cwd=ROOT,
        env=_cli_environment(),
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.stderr or not completed.stdout.endswith(b"\n") or completed.stdout.count(b"\n") != 1:
        raise TopologyError("IS_INTEGRATED_STAGE", "fixed child CLI stream contract differs")
    try:
        envelope = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TopologyError("IS_INTEGRATED_STAGE", "fixed child CLI output is not one JSON envelope") from error
    if not isinstance(envelope, dict) or envelope.get("schema_version") != "incidentseal-cli-envelope/v1":
        raise TopologyError("IS_INTEGRATED_STAGE", "fixed child CLI envelope version differs")
    if envelope.get("process_exit_code") != completed.returncode:
        raise TopologyError("IS_INTEGRATED_STAGE", "fixed child process and envelope exits differ")
    if completed.returncode not in allowed_exits:
        io_error = completed.returncode in {70, 74}
        raise TopologyError("IS_INTEGRATED_STAGE", f"fixed child CLI exited {completed.returncode}", io_error=io_error)
    return envelope, _digest(completed.stdout)


def _case(
    case_id: str,
    *,
    lifecycle: str | None,
    run_verdict: str | None,
    observation_verdict: str | None,
    exit_code: int,
    evidence: list[str],
) -> dict[str, Any]:
    expected = EXPECTED_CASE_MAP.get(case_id)
    if expected is None:
        raise TopologyError("IS_INTEGRATED_STATE", f"unknown integrated case: {case_id}")
    observed = (case_id, expected[1], lifecycle, run_verdict, observation_verdict, exit_code)
    if observed != expected:
        raise TopologyError("IS_INTEGRATED_STATE", f"integrated state differs for {case_id}")
    return {
        "id": case_id,
        "surface": expected[1],
        "lifecycle": lifecycle,
        "run_verdict": run_verdict,
        "observation_verdict": observation_verdict,
        "exit_code": exit_code,
        "evidence": evidence,
    }


def _check_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise TopologyError("IS_INTEGRATED_STAGE", "stage checks are absent")
    result: dict[str, dict[str, Any]] = {}
    for item in checks:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in result:
            raise TopologyError("IS_INTEGRATED_STAGE", "stage checks are malformed or duplicated")
        result[item["id"]] = item
    return result


def _require_checks(stage: str, data: dict[str, Any], required: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    checks = _check_map(data)
    failed = [item["id"] for item in checks.values() if item.get("status") != "PASS"]
    missing = [item for item in required if item not in checks]
    if failed or missing or data.get("verdict") != "PASS":
        raise TopologyError("IS_INTEGRATED_STAGE", f"{stage} checks differ: failed={failed}, missing={missing}")
    return checks


def _images(data: dict[str, Any]) -> list[dict[str, str]]:
    images = data.get("images")
    if not isinstance(images, list):
        raise TopologyError("IS_INTEGRATED_IDENTITY", "stage image evidence is absent")
    projected = sorted(
        ({"role": str(item.get("role")), "image_id": str(item.get("image_id"))} for item in images if isinstance(item, dict)),
        key=lambda item: item["role"],
    )
    if [item["role"] for item in projected] != ["database", "migration", "node-runner", "python-runner"]:
        raise TopologyError("IS_INTEGRATED_IDENTITY", "stage image roles differ")
    if any(not item["image_id"].startswith("sha256:") for item in projected):
        raise TopologyError("IS_INTEGRATED_IDENTITY", "stage image identity differs")
    return projected


def _boundary(docker: str, protected: set[str]) -> dict[str, Any]:
    containers = sorted(line for line in _run(docker, ["ps", "-a", "--format", "{{.Names}}", "--filter", "name=incidentseal"]).stdout.splitlines() if line)
    networks = sorted(
        line for line in _run(docker, ["network", "ls", "--format", "{{.Name}}"]).stdout.splitlines()
        if line.startswith("incidentseal")
    )
    available = _volume_names(docker)
    incidentseal_volumes = {name for name in available if name.startswith("incidentseal-")}
    snapshot = _volume_snapshot(docker, protected)
    if containers or networks or incidentseal_volumes != protected or set(snapshot) != protected:
        raise TopologyError("IS_INTEGRATED_CUSTODY", "integrated stage boundary contains unexpected custody")
    return {
        "containers": containers,
        "networks": networks,
        "incidentseal_volumes": sorted(incidentseal_volumes),
        "protected_volume_identity": snapshot,
    }


def _receipt_stage() -> dict[str, Any]:
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="incidentseal-integrated-receipt-") as temporary:
        custody = _safe_temporary(Path(temporary))
        temporary_path = custody
        output_root = custody / "bundles"
        materialize_args = (
            "receipt", "materialize", "--receipt", str(RECEIPT_PATH), "--source-root", str(RECEIPT_SOURCE),
            "--output-root", str(output_root), "--json",
        )
        first, first_digest = _run_cli(materialize_args, allowed_exits={0})
        second, second_digest = _run_cli(materialize_args, allowed_exits={0})
        if first.get("command") != "receipt.materialize" or first.get("verdict") != "PASS":
            raise TopologyError("IS_INTEGRATED_RECEIPT", "receipt materialization differs")
        if second.get("data", {}).get("idempotent") is not True:
            raise TopologyError("IS_INTEGRATED_RECEIPT", "receipt materialization is not idempotent")
        bundle = Path(str(first.get("data", {}).get("bundle_path", ""))).resolve(strict=True)
        if custody not in bundle.parents:
            raise TopologyError("IS_INTEGRATED_CUSTODY", "receipt bundle escaped temporary custody")
        receipt = bundle / "receipt.json"
        artifact = bundle / "artifacts" / "result.json"
        expected_digest = str(first.get("data", {}).get("receipt_digest", ""))
        bundle_digest = _tree_digest(bundle)

        def verify(expected: str | None) -> tuple[dict[str, Any], str]:
            arguments = ["receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle)]
            if expected is not None:
                arguments.extend(["--expected-digest", expected])
            arguments.append("--json")
            return _run_cli(tuple(arguments), allowed_exits={0, 10, 11, 12})

        exact, exact_digest = verify(expected_digest)
        unbound, unbound_digest = verify(None)
        invalid, invalid_digest = verify("sha256:" + "0" * 64)
        artifact.write_bytes(b'{"status":"FAIL"}\n')
        corrupt, corrupt_digest = verify(expected_digest)
        shutil.copyfile(RECEIPT_SOURCE / "artifacts" / "result.json", artifact)
        artifact.unlink()
        missing, missing_digest = verify(expected_digest)
        observations = {
            "exact": exact,
            "unbound": unbound,
            "invalid": invalid,
            "corrupt": corrupt,
            "missing": missing,
        }
        expected_states = {
            "exact": (0, "PASS", "MATCH"),
            "unbound": (11, "INCONCLUSIVE", "UNBOUND"),
            "invalid": (12, "INVALID", "MISMATCH"),
            "corrupt": (10, "FAIL", "MATCH"),
            "missing": (11, "INCONCLUSIVE", "MATCH"),
        }
        for name, (exit_code, verdict, identity) in expected_states.items():
            value = observations[name]
            if value.get("process_exit_code") != exit_code or value.get("verdict") != verdict or value.get("data", {}).get("identity_status") != identity:
                raise TopologyError("IS_INTEGRATED_RECEIPT", f"receipt {name} state differs")
        cases = [
            _case("receipt-exact-identity", lifecycle=None, run_verdict=None, observation_verdict="PASS", exit_code=0, evidence=["receipt.verify:exact"]),
            _case("receipt-unbound-identity", lifecycle=None, run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11, evidence=["receipt.verify:unbound"]),
            _case("receipt-missing-artifact", lifecycle=None, run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11, evidence=["receipt.verify:missing"]),
            _case("receipt-corrupt-artifact", lifecycle=None, run_verdict=None, observation_verdict="FAIL", exit_code=10, evidence=["receipt.verify:corrupt"]),
            _case("receipt-invalid-identity", lifecycle=None, run_verdict=None, observation_verdict="INVALID", exit_code=12, evidence=["receipt.verify:mismatch"]),
        ]
        semantic = {
            "receipt_digest": expected_digest,
            "bundle_digest": bundle_digest,
            "materialize_idempotent": True,
            "cases": [{key: value[key] for key in ("id", "lifecycle", "run_verdict", "observation_verdict", "exit_code")} for value in cases],
        }
        stage = {
            "id": "receipt-state-matrix",
            "commands": ["receipt.materialize", "receipt.verify"],
            "invocation_ids": [first["invocation_id"], second["invocation_id"], exact["invocation_id"], unbound["invocation_id"], invalid["invocation_id"], corrupt["invocation_id"], missing["invocation_id"]],
            "output_digests": [first_digest, second_digest, exact_digest, unbound_digest, invalid_digest, corrupt_digest, missing_digest],
            "cases": cases,
            "semantic": semantic,
            "semantic_digest": _digest(canonical_bytes(semantic)),
            "temporary_custody_removed": True,
        }
    if temporary_path is None or temporary_path.exists():
        raise TopologyError("IS_INTEGRATED_CUSTODY", "receipt stage temporary custody remained")
    return stage


def _child_stage(stage_id: str, mapper: Callable[[dict[str, Any]], tuple[list[dict[str, Any]], dict[str, Any]]]) -> dict[str, Any]:
    arguments = FIXED_STAGE_ARGUMENTS[stage_id]
    envelope, output_digest = _run_cli(arguments, allowed_exits={0, 10})
    if envelope.get("command") != f"topology.{stage_id}":
        raise TopologyError("IS_INTEGRATED_STAGE", f"{stage_id} command identity differs")
    if envelope.get("process_exit_code") == 10 and envelope.get("verdict") == "FAIL":
        raise CompositeProductFailure(stage_id, envelope, output_digest)
    if envelope.get("process_exit_code") != 0 or envelope.get("verdict") != "PASS":
        raise TopologyError("IS_INTEGRATED_STAGE", f"{stage_id} did not return PASS")
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise TopologyError("IS_INTEGRATED_STAGE", f"{stage_id} data is absent")
    cases, semantic = mapper(data)
    return {
        "id": stage_id,
        "commands": [f"topology.{stage_id}"],
        "invocation_ids": [envelope["invocation_id"]],
        "output_digests": [output_digest],
        "data_digest": _digest(canonical_bytes(data)),
        "cases": cases,
        "semantic": semantic,
        "semantic_digest": _digest(canonical_bytes(semantic)),
        "temporary_custody_removed": True,
    }


def _reliability_semantic(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    required = (
        "fresh-bootstrap", "fresh-python-runner", "fresh-node-runner", "fresh-database-rows",
        "forced-verification-failure", "invalid-input-distinct", "execution-failure-distinct",
        "failed-run-no-database-row", "post-failure-recovery", "host-cancellation-distinct",
        "restart-persistence", "orphan-detection", "protected-volumes-unchanged", "disposable-teardown",
    )
    checks = _require_checks("reliability", data, required)
    forced = checks["forced-verification-failure"].get("observed", {})
    malformed = checks["invalid-input-distinct"].get("observed", {})
    outage = checks["execution-failure-distinct"].get("observed", {})
    cancelled = checks["host-cancellation-distinct"].get("observed", {})
    if forced.get("lifecycle") != "completed" or forced.get("verification_verdict") != "FAIL":
        raise TopologyError("IS_INTEGRATED_STATE", "completed product failure evidence differs")
    malformed_runners = [malformed.get("python-runner"), malformed.get("node-runner")]
    if (
        malformed.get("verification_verdict") != "INVALID"
        or malformed.get("database_rows_unchanged") is not True
        or any(not isinstance(item, dict) or item.get("output_exists") is not False for item in malformed_runners)
    ):
        raise TopologyError("IS_INTEGRATED_STATE", "malformed input no-run evidence differs")
    if outage.get("lifecycle") != "failed" or outage.get("verification_verdict") is not None:
        raise TopologyError("IS_INTEGRATED_STATE", "database outage lifecycle evidence differs")
    if cancelled.get("lifecycle") != "cancelled" or cancelled.get("verification_verdict") is not None:
        raise TopologyError("IS_INTEGRATED_STATE", "host cancellation lifecycle evidence differs")
    cases = [
        _case("reliability-completed-pass", lifecycle="completed", run_verdict="PASS", observation_verdict="PASS", exit_code=0, evidence=["fresh-python-runner", "fresh-node-runner", "fresh-database-rows"]),
        _case("reliability-completed-fail", lifecycle="completed", run_verdict="FAIL", observation_verdict="FAIL", exit_code=10, evidence=["forced-verification-failure"]),
        _case("reliability-malformed-input", lifecycle=None, run_verdict=None, observation_verdict="INVALID", exit_code=12, evidence=["invalid-input-distinct:no-run-output-no-row"]),
        _case("reliability-database-outage", lifecycle="failed", run_verdict=None, observation_verdict=None, exit_code=21, evidence=["execution-failure-distinct", "failed-run-no-database-row"]),
        _case("reliability-host-cancelled", lifecycle="cancelled", run_verdict=None, observation_verdict=None, exit_code=20, evidence=["host-cancellation-distinct"]),
    ]
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        raise TopologyError("IS_INTEGRATED_STAGE", "reliability semantic evidence is absent")
    semantic = {
        "contract_digest": data.get("contract_digest"),
        "images": _images(data),
        "result_state_digest": _digest(canonical_bytes(evidence)),
        "cases": [{key: value[key] for key in ("id", "lifecycle", "run_verdict", "observation_verdict", "exit_code")} for value in cases],
    }
    return cases, semantic


def _journal_semantic(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    required = (
        "run-events-completed-pass", "run-events-stale-authority", "run-events-superseded-attempt",
        "transactional-insert-and-replay", "database-conflict-and-state-rejection", "immutable-update-denied",
        "immutable-delete-denied", "immutable-truncate-denied", "runner-table-read-denied",
        "retained-row-count", "restart-persistence-and-stream", "protected-volume-identities-unchanged",
        "disposable-teardown",
    )
    _require_checks("journal", data, required)
    streams = data.get("results", {}).get("streams")
    if not isinstance(streams, dict):
        raise TopologyError("IS_INTEGRATED_STAGE", "journal streams are absent")
    stale = streams.get("stale-authority", {})
    superseded = streams.get("superseded-attempt", {})
    if stale.get("exit_code") != 22 or superseded.get("exit_code") != 23:
        raise TopologyError("IS_INTEGRATED_STATE", "journal lifecycle exits differ")
    cases = [
        _case("journal-stale", lifecycle="stale", run_verdict=None, observation_verdict=None, exit_code=22, evidence=["run-events-stale-authority"]),
        _case("journal-superseded", lifecycle="superseded", run_verdict=None, observation_verdict=None, exit_code=23, evidence=["run-events-superseded-attempt"]),
    ]
    semantic_streams = {
        key: {"exit_code": value.get("exit_code"), "stream_digest": value.get("stream_digest")}
        for key, value in sorted(streams.items())
    }
    semantic = {
        "contract_digest": data.get("contract_digest"),
        "images": _images(data),
        "streams": semantic_streams,
        "inserted_records": data.get("results", {}).get("inserted_records"),
        "exact_replays": data.get("results", {}).get("exact_replays"),
    }
    return cases, semantic


def _recovery_semantic(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    required = (
        "fresh-disposable-bootstrap", "active-owner-defers-without-mutation", "unowned-orphan-defers-without-mutation",
        "owned-orphan-stop-reobserve-replay", "running-cancellation-terminal", "nonzero-process-failure-terminal",
        "authority-drift-stale-terminal", "effect-state-separation", "durable-pending-resume",
        "concurrent-recoverer-fenced", "runner-recovery-state-denied", "restart-persistence",
        "recovery-never-fabricates-run-verdict", "protected-volume-identities-unchanged", "disposable-teardown",
    )
    checks = _require_checks("recovery", data, required)
    effects = checks["effect-state-separation"].get("observed", {})
    stale = checks["authority-drift-stale-terminal"].get("observed", {})
    concurrent = checks["concurrent-recoverer-fenced"].get("observed", {})
    safe = checks["owned-orphan-stop-reobserve-replay"].get("observed", {})
    if (
        safe.get("decisions") != ["IS_RECOVERY_ORPHAN_RUNNING", "IS_RECOVERY_SAFE_REPLAY"]
        or safe.get("event_count") != 4
        or effects.get("conflict_exit") != 21
        or effects.get("ambiguous_exit") != 11
        or stale.get("exit_code") != 22
        or concurrent.get("second_holder_error") != "IS_RECOVERY_ACTIVE_OWNER"
    ):
        raise TopologyError("IS_INTEGRATED_STATE", "recovery state exits differ")
    cases = [
        _case("recovery-safe-replay", lifecycle="completed", run_verdict=None, observation_verdict="PASS", exit_code=0, evidence=["owned-orphan-stop-reobserve-replay"]),
        _case("recovery-ambiguous-effects", lifecycle="running", run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11, evidence=["effect-state-separation:ambiguous"]),
        _case("recovery-conflicting-effects", lifecycle="running", run_verdict=None, observation_verdict="FAIL", exit_code=21, evidence=["effect-state-separation:conflict"]),
        _case("recovery-authority-stale", lifecycle="stale", run_verdict=None, observation_verdict="PASS", exit_code=22, evidence=["authority-drift-stale-terminal"]),
        _case("recovery-concurrent-holder", lifecycle="running", run_verdict=None, observation_verdict="INCONCLUSIVE", exit_code=11, evidence=["concurrent-recoverer-fenced"]),
    ]
    semantic = {
        "contract_digest": data.get("contract_digest"),
        "images": _images(data),
        "decisions": {
            "safe_replay": checks["owned-orphan-stop-reobserve-replay"].get("observed"),
            "effect_state": effects,
            "authority_stale": stale,
            "concurrent_holder_error": concurrent.get("second_holder_error"),
            "noncompleted_verdict_rows": checks["recovery-never-fabricates-run-verdict"].get("observed", {}).get("noncompleted_verdict_rows"),
        },
    }
    return cases, semantic


def _backup_semantic(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    required = (
        "source-synthetic-state", "source-writes-blocked", "custom-archive-created", "normalized-toc-bound", "clean-distinct-target",
        "restored-state-equivalence", "restored-negative-privileges", "restart-persistence",
        "protected-volume-identities-unchanged", "disposable-teardown",
    )
    _require_checks("backup-restore", data, required)
    receipt = data.get("receipt")
    if not isinstance(receipt, dict) or receipt.get("verification_verdict") != "PASS":
        raise TopologyError("IS_INTEGRATED_STAGE", "backup receipt is absent or invalid")
    backup = receipt.get("backup", {})
    restore = receipt.get("restore", {})
    source = receipt.get("source", {})
    negatives = restore.get("negative_privileges")
    if not isinstance(negatives, dict) or set(negatives.values()) != {"denied"}:
        raise TopologyError("IS_INTEGRATED_STATE", "restored negative privileges differ")
    cases = [
        _case("backup-restore-complete", lifecycle="completed", run_verdict=None, observation_verdict="PASS", exit_code=0, evidence=["custom-archive-created", "normalized-toc-bound", "clean-distinct-target", "restored-state-equivalence"]),
        _case("backup-restore-negative-privileges", lifecycle="completed", run_verdict=None, observation_verdict="PASS", exit_code=0, evidence=["restored-negative-privileges", "restart-persistence"]),
        _case("backup-restore-teardown", lifecycle="completed", run_verdict=None, observation_verdict="PASS", exit_code=0, evidence=["protected-volume-identities-unchanged", "disposable-teardown"]),
    ]
    restored_state = {
        "schema_digest": restore.get("schema_digest"),
        "journal_digest": restore.get("journal_digest"),
        "verification_results_digest": restore.get("verification_results_digest"),
        "role_digest": restore.get("role_digest"),
    }
    semantic = {
        "contract_digest": data.get("contract_digest"),
        "images": _images(data),
        "normalized_toc_digest": backup.get("normalized_toc_digest"),
        "toc_entries": backup.get("toc_entries"),
        "restored_state": restored_state,
        "negative_privileges": negatives,
        "source_counts": {
            "journal_runs": source.get("journal", {}).get("run_count"),
            "journal_events": source.get("journal", {}).get("event_count"),
            "verification_results": source.get("verification_results", {}).get("row_count"),
        },
        "raw_archive_receipt": {
            "receipt_digest": receipt.get("receipt_digest"),
            "archive_digest": backup.get("archive_digest"),
            "archive_bytes": backup.get("archive_bytes"),
        },
    }
    return cases, semantic


def _cross_cycle(cycles: list[dict[str, Any]], root_identity: dict[str, str]) -> dict[str, Any]:
    if len(cycles) != REPETITIONS:
        raise TopologyError("IS_INTEGRATED_REPEATABILITY", "complete cycle count differs")
    by_cycle = [{stage["id"]: stage for stage in cycle["stages"]} for cycle in cycles]
    if any(list(items) != list(STAGE_ORDER) for items in by_cycle):
        raise TopologyError("IS_INTEGRATED_COMPOSITION", "observed stage order differs")
    image_sets = []
    contract_sets = []
    for items in by_cycle:
        stage_images = [items[stage]["semantic"]["images"] for stage in STAGE_ORDER[1:]]
        if any(value != stage_images[0] for value in stage_images[1:]):
            raise TopologyError("IS_INTEGRATED_IDENTITY", "exact images differ between stages")
        image_sets.append(stage_images[0])
        contract_sets.append([items[stage]["semantic"]["contract_digest"] for stage in STAGE_ORDER[1:]])
    comparisons = {
        "same_exact_images": image_sets[0] == image_sets[1],
        "same_contract_digest": contract_sets[0] == contract_sets[1] and len(set(contract_sets[0] + contract_sets[1])) == 1,
        "same_semantic_receipts": by_cycle[0]["receipt-state-matrix"]["semantic"] == by_cycle[1]["receipt-state-matrix"]["semantic"],
        "same_journal_streams": by_cycle[0]["journal-probe"]["semantic"]["streams"] == by_cycle[1]["journal-probe"]["semantic"]["streams"],
        "same_recovery_decisions": by_cycle[0]["recovery-probe"]["semantic"]["decisions"] == by_cycle[1]["recovery-probe"]["semantic"]["decisions"],
        "same_normalized_toc": by_cycle[0]["backup-restore-probe"]["semantic"]["normalized_toc_digest"] == by_cycle[1]["backup-restore-probe"]["semantic"]["normalized_toc_digest"],
        "same_restored_state": by_cycle[0]["backup-restore-probe"]["semantic"]["restored_state"] == by_cycle[1]["backup-restore-probe"]["semantic"]["restored_state"],
        "same_negative_privileges": by_cycle[0]["backup-restore-probe"]["semantic"]["negative_privileges"] == by_cycle[1]["backup-restore-probe"]["semantic"]["negative_privileges"],
        "protected_volumes_unchanged": all(cycle["protected_volume_identity"] == root_identity for cycle in cycles),
        "teardown_between_stages": all(stage["custody"]["unchanged"] for cycle in cycles for stage in cycle["stages"]),
        "teardown_after_cycle": all(cycle["teardown_complete"] for cycle in cycles),
    }
    if not all(comparisons.values()):
        failed = sorted(key for key, value in comparisons.items() if not value)
        raise TopologyError("IS_INTEGRATED_REPEATABILITY", f"cross-cycle comparison failed: {failed}")
    raw_archives = [items["backup-restore-probe"]["semantic"]["raw_archive_receipt"] for items in by_cycle]
    if any(not str(item.get("archive_digest", "")).startswith("sha256:") or not str(item.get("receipt_digest", "")).startswith("sha256:") for item in raw_archives):
        raise TopologyError("IS_INTEGRATED_IDENTITY", "per-receipt raw archive identity is absent")
    return {
        **comparisons,
        "archive_identity_mode": "per-receipt-raw-plus-stable-normalized-toc",
        "comparison_excludes": list(COMPARISON_EXCLUDES),
        "raw_archive_receipts": raw_archives,
    }


def _failure_result(
    *,
    implementation_lock_digest: str,
    matrix: dict[str, Any],
    protected: set[str],
    root_boundary: dict[str, Any],
    cycles: list[dict[str, Any]],
    failure: CompositeProductFailure,
    final_boundary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "incidentseal-integrated-recovery-probe/v1",
        "verdict": "FAIL",
        "mode": "platform-validation",
        "claim_scope": "fixed-synthetic-repeated-integrated-receipt-and-recovery-only",
        "contract_digest": _sha256_file(CONTRACT_PATH),
        "matrix_digest": matrix["matrix_digest"],
        "integrated_recovery_implementation_lock_digest": implementation_lock_digest,
        "cycles": cycles,
        "failure": {
            "stage": failure.stage,
            "invocation_id": failure.envelope.get("invocation_id"),
            "process_exit_code": failure.envelope.get("process_exit_code"),
            "verification_verdict": failure.envelope.get("verdict"),
            "output_digest": failure.output_digest,
        },
        "protected_volumes": sorted(protected),
        "protected_volume_identity_unchanged": final_boundary["protected_volume_identity"] == root_boundary["protected_volume_identity"],
        "containers_removed": not final_boundary["containers"],
        "networks_removed": not final_boundary["networks"],
        "approval_accessed": False,
        "workflow_executed": False,
        "runtime_started": True,
    }


def integrated_recovery_probe() -> dict[str, Any]:
    """Run the exact five-stage matrix twice with host-only Docker authority."""

    implementation_lock_digest = validate_integrated_recovery_implementation_lock()
    matrix_value = _load(MATRIX_PATH)
    try:
        matrix = validate_matrix(matrix_value)
    except Exception as error:
        raise TopologyError("IS_INTEGRATED_CONTRACT", "integrated matrix contract is invalid") from error
    docker = _docker_executable()
    _volume_lock, protected = _load_retained_volume_lock(docker)
    root_boundary = _boundary(docker, protected)
    root_identity = root_boundary["protected_volume_identity"]
    cycles: list[dict[str, Any]] = []
    dispatch: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
        ("receipt-state-matrix", _receipt_stage),
        ("reliability-probe", lambda: _child_stage("reliability-probe", _reliability_semantic)),
        ("journal-probe", lambda: _child_stage("journal-probe", _journal_semantic)),
        ("recovery-probe", lambda: _child_stage("recovery-probe", _recovery_semantic)),
        ("backup-restore-probe", lambda: _child_stage("backup-restore-probe", _backup_semantic)),
    )
    if [item[0] for item in dispatch] != list(STAGE_ORDER):
        raise TopologyError("IS_INTEGRATED_COMPOSITION", "integrated dispatch order differs")

    for repetition in range(1, REPETITIONS + 1):
        stages: list[dict[str, Any]] = []
        for stage_id, execute_stage in dispatch:
            before = _boundary(docker, protected)
            try:
                stage = execute_stage()
            except CompositeProductFailure as failure:
                final_boundary = _boundary(docker, protected)
                return _failure_result(
                    implementation_lock_digest=implementation_lock_digest,
                    matrix=matrix,
                    protected=protected,
                    root_boundary=root_boundary,
                    cycles=cycles,
                    failure=failure,
                    final_boundary=final_boundary,
                )
            after = _boundary(docker, protected)
            unchanged = before == after and after["protected_volume_identity"] == root_identity
            if not unchanged:
                raise TopologyError("IS_INTEGRATED_CUSTODY", f"{stage_id} changed protected or disposable custody")
            stage["custody"] = {"before": before, "after": after, "unchanged": unchanged}
            stages.append(stage)
        final_cycle_boundary = _boundary(docker, protected)
        case_ids = [case["id"] for stage in stages for case in stage["cases"]]
        if case_ids != [item[0] for item in EXPECTED_CASES]:
            raise TopologyError("IS_INTEGRATED_STATE", "complete integrated case order differs")
        cycles.append({
            "repetition": repetition,
            "stages": stages,
            "case_count": len(case_ids),
            "protected_volume_identity": final_cycle_boundary["protected_volume_identity"],
            "teardown_complete": final_cycle_boundary == root_boundary,
        })

    cross_cycle = _cross_cycle(cycles, root_identity)
    final_boundary = _boundary(docker, protected)
    if final_boundary != root_boundary:
        raise TopologyError("IS_INTEGRATED_CUSTODY", "integrated final custody differs")
    return {
        "schema_version": "incidentseal-integrated-recovery-probe/v1",
        "verdict": "PASS",
        "mode": "platform-validation",
        "claim_scope": "fixed-synthetic-repeated-integrated-receipt-and-recovery-only",
        "contract_digest": _sha256_file(CONTRACT_PATH),
        "matrix_digest": matrix["matrix_digest"],
        "integrated_recovery_implementation_lock_digest": implementation_lock_digest,
        "repetitions": REPETITIONS,
        "stage_order": list(STAGE_ORDER),
        "command_identities": list(COMMANDS),
        "case_count_per_cycle": len(EXPECTED_CASES),
        "cycles": cycles,
        "cross_cycle": cross_cycle,
        "protected_volumes": sorted(protected),
        "protected_volume_identity": root_identity,
        "containers_removed": True,
        "networks_removed": True,
        "disposable_volumes_removed": True,
        "temporary_custody_removed": True,
        "approval_accessed": False,
        "workflow_executed": False,
        "runtime_started": True,
    }
