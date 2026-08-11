"""Disposable real failure, staleness, cancellation, and resume probe."""

from __future__ import annotations

import _thread
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.approval import ApprovalResult  # noqa: E402
from incidentseal.manifest import load_manifest  # noqa: E402
from incidentseal.workflow import (  # noqa: E402
    RunArchive,
    _active_key,
    _atomic_json,
    execute_workflow,
    inspect_repository,
    read_archive_events,
)


REMOTE = "https://github.com/example/incidentseal-disposable-recovery.git"


def run(command: list[str], cwd: Path, *, binary: bool = False) -> str | bytes:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, check=True)
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def create_repository(parent: Path, name: str, source: str, *, maximum: int = 65536, revision: int = 1):
    repository = parent / name
    repository.mkdir()
    run(["git", "init", "--quiet"], repository)
    run(["git", "config", "user.email", "incidentseal@example.invalid"], repository)
    run(["git", "config", "user.name", "IncidentSeal Probe"], repository)
    run(["git", "remote", "add", "origin", REMOTE + f"/{name}.git"], repository)
    (repository / ".gitignore").write_text("workflow*.json\n", encoding="utf-8")
    (repository / "check.py").write_text(source, encoding="utf-8")
    run(["git", "add", ".gitignore", "check.py"], repository)
    run(["git", "commit", "--quiet", "-m", name], repository)
    commit = run(["git", "rev-parse", "HEAD"], repository)
    tree = run(["git", "ls-tree", "-r", "-z", "--full-tree", commit], repository, binary=True)
    manifest = {
        "schema_version": "incidentseal-workflow/v1",
        "workflow_id": f"probe.{name}",
        "revision": revision,
        "repository": {
            "remote": REMOTE + f"/{name}.git",
            "commit": commit,
            "tree_digest": "sha256:" + hashlib.sha256(tree).hexdigest(),
        },
        "claim": {"id": "probe.result", "statement": "Disposable recovery scenario passed.", "required_steps": ["check"]},
        "security": {
            "container_engine_control": "host-cli-only", "docker_socket": "denied", "privileged": False,
            "host_network": False, "runtime_egress": "denied", "secrets": "denied", "host_mount_mode": "staged-read-only",
        },
        "steps": [{
            "id": "check", "runner": "python", "command": ["python", "check.py"], "cwd": ".", "depends_on": [],
            "timeout_seconds": 120, "expected_exit_codes": [0], "inputs": ["check.py"], "outputs": [], "network": "none",
            "capture": {"stdout": "full", "stderr": "full", "max_bytes": maximum},
        }],
        "evidence_policy": {
            "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
            "preserve_lifecycle": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
            "retain_attempts": "all",
        },
    }
    path = repository / "workflow.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return repository, load_manifest(path), manifest


def match(document) -> ApprovalResult:
    return ApprovalResult("MATCH", document.digest, None, None, (), None, None)


def execute(document, state: Path, inspector=match):
    return execute_workflow(
        document,
        approval_inspector=inspector,
        run_root=state,
        permission_checker=lambda path: True,
    )


def remaining(run_id: str) -> int:
    value = run(["docker", "ps", "-aq", "--filter", f"label=dev.incidentseal.workflow-run={run_id}"], ROOT)
    return 0 if not value else len(str(value).splitlines())


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="incidentseal-real-workflow-recovery-") as temporary_value:
        temporary = Path(temporary_value)
        results: dict[str, dict[str, object]] = {}

        _, failure_document, _ = create_repository(temporary, "failure", "raise SystemExit(7)\n")
        failure = execute(failure_document, temporary / "failure-state")
        failure_events, failure_exit = read_archive_events(temporary / "failure-state", failure.data["run_id"])
        results["failure"] = {
            "verdict": failure.verdict, "lifecycle": failure.lifecycle, "exit": failure.exit_code,
            "stream_exit": failure_exit, "events": len(failure_events), "containers": remaining(failure.data["run_id"]),
        }

        _, capture_document, _ = create_repository(temporary, "capture", "print('capture-overflow')\n", maximum=1)
        capture = execute(capture_document, temporary / "capture-state")
        capture_events, capture_exit = read_archive_events(temporary / "capture-state", capture.data["run_id"])
        results["inconclusive"] = {
            "verdict": capture.verdict, "lifecycle": capture.lifecycle, "exit": capture.exit_code,
            "stream_exit": capture_exit, "events": len(capture_events), "containers": remaining(capture.data["run_id"]),
        }

        _, stale_document, _ = create_repository(temporary, "stale", "print('not-run')\n")
        inspections = 0

        def expiring(document):
            nonlocal inspections
            inspections += 1
            if inspections <= 2:
                return match(document)
            return ApprovalResult(
                "MISMATCH", "sha256:" + "f" * 64, None, None, ("manifest_digest",),
                "IS_APPROVAL_MISMATCH", "approval bindings do not match the manifest",
            )

        stale = execute(stale_document, temporary / "stale-state", expiring)
        stale_events, stale_exit = read_archive_events(temporary / "stale-state", stale.data["run_id"])
        results["stale"] = {
            "verdict": stale.verdict, "lifecycle": stale.lifecycle, "exit": stale.exit_code,
            "stream_exit": stale_exit, "events": len(stale_events), "containers": remaining(stale.data["run_id"]),
        }

        _, resume_document, resume_manifest = create_repository(temporary, "resume", "print('resumed')\n")
        resume_state = temporary / "resume-state"
        (resume_state / "runs").mkdir(parents=True)
        (resume_state / "active").mkdir()
        snapshot = inspect_repository(resume_document)
        interrupted_id = str(uuid.uuid4())
        archive = RunArchive(resume_state, interrupted_id, resume_document, match(resume_document))
        archive.create()
        archive.append("run.queued", "queued", payload={"repository_remote": snapshot.remote, "commit": snapshot.commit, "tree_digest": snapshot.tree_digest})
        archive.append("run.started", "running", payload={"resumed": False})
        key = _active_key(resume_document, snapshot)
        _atomic_json(
            resume_state / "active" / f"{key}.json",
            {"schema_version": "incidentseal-workflow-active-pointer/v1", "active_key": key, "run_id": interrupted_id},
        )
        resumed = execute(resume_document, resume_state)
        resumed_events, resumed_exit = read_archive_events(resume_state, interrupted_id)
        results["resume"] = {
            "same_run": resumed.data["run_id"] == interrupted_id, "verdict": resumed.verdict, "lifecycle": resumed.lifecycle,
            "exit": resumed.exit_code, "stream_exit": resumed_exit, "events": len(resumed_events),
            "active_removed": not (resume_state / "active" / f"{key}.json").exists(), "containers": remaining(interrupted_id),
        }

        crash_repository, crash_document, _ = create_repository(temporary, "crash-resume", "print('replayed-after-crash')\n")
        crash_state = temporary / "crash-resume-state"
        crash_source = (
            "import os,sys\n"
            "from pathlib import Path\n"
            "import incidentseal.workflow as w\n"
            "from incidentseal.approval import ApprovalResult\n"
            "from incidentseal.manifest import load_manifest\n"
            "old=w.RunArchive.append\n"
            "def append(self,event_type,lifecycle,**kwargs):\n"
            " value=old(self,event_type,lifecycle,**kwargs)\n"
            " if event_type=='step.started': os._exit(91)\n"
            " return value\n"
            "w.RunArchive.append=append\n"
            "d=load_manifest(sys.argv[1])\n"
            "def match(x): return ApprovalResult('MATCH',x.digest,None,None,(),None,None)\n"
            "w.execute_workflow(d,approval_inspector=match,run_root=Path(sys.argv[2]),permission_checker=lambda path:True)\n"
        )
        crash_environment = os.environ.copy()
        crash_environment["PYTHONPATH"] = str(ROOT / "src")
        crashed = subprocess.run(
            [sys.executable, "-c", crash_source, str(crash_document.path), str(crash_state)],
            cwd=crash_repository, env=crash_environment, capture_output=True, timeout=60, check=False,
        )
        pointers = list((crash_state / "active").glob("*.json"))
        if crashed.returncode != 91 or len(pointers) != 1:
            raise RuntimeError(f"crash fixture did not stop at the retained boundary: {crashed.returncode}")
        crash_pointer = json.loads(pointers[0].read_text(encoding="utf-8"))
        crash_run_id = crash_pointer["run_id"]
        crashed_candidates = remaining(crash_run_id)
        crash_resumed = execute(crash_document, crash_state)
        crash_events, crash_exit = read_archive_events(crash_state, crash_run_id)
        results["started_step_replay"] = {
            "crash_exit": crashed.returncode,
            "runtime_retained_before_resume": crashed_candidates == 1,
            "same_run": crash_resumed.data["run_id"] == crash_run_id,
            "verdict": crash_resumed.verdict,
            "lifecycle": crash_resumed.lifecycle,
            "exit": crash_resumed.exit_code,
            "stream_exit": crash_exit,
            "events": len(crash_events),
            "containers": remaining(crash_run_id),
        }

        _, unknown_document, _ = create_repository(temporary, "unknown-runtime", "print('must-not-run')\n")
        unknown_state = temporary / "unknown-runtime-state"
        (unknown_state / "runs").mkdir(parents=True)
        (unknown_state / "active").mkdir()
        unknown_snapshot = inspect_repository(unknown_document)
        unknown_id = str(uuid.uuid4())
        unknown_archive = RunArchive(unknown_state, unknown_id, unknown_document, match(unknown_document))
        unknown_archive.create()
        unknown_archive.append("run.queued", "queued")
        unknown_archive.append("run.started", "running")
        unknown_key = _active_key(unknown_document, unknown_snapshot)
        _atomic_json(
            unknown_state / "active" / f"{unknown_key}.json",
            {"schema_version": "incidentseal-workflow-active-pointer/v1", "active_key": unknown_key, "run_id": unknown_id},
        )
        runtime_lock = json.loads((ROOT / "requirements" / "topology-runtime.lock.json").read_text(encoding="utf-8"))
        python_image = next(item["image_id"] for item in runtime_lock["images"] if item["role"] == "python-runner")
        lookalike = run(
            ["docker", "create", "--label", f"dev.incidentseal.workflow-run={unknown_id}", python_image],
            ROOT,
        )
        unknown = execute(unknown_document, unknown_state)
        unknown_events, unknown_exit = read_archive_events(unknown_state, unknown_id)
        untouched = remaining(unknown_id) == 1
        run(["docker", "rm", "--force", str(lookalike)], ROOT)
        results["unknown_runtime"] = {
            "verdict": unknown.verdict, "lifecycle": unknown.lifecycle, "exit": unknown.exit_code,
            "stream_exit": unknown_exit, "events": len(unknown_events), "unowned_runtime_untouched": untouched,
            "containers_after_probe_cleanup": remaining(unknown_id),
        }
        terminal_bytes = (resume_state / "runs" / interrupted_id / "events.jsonl").read_bytes()
        second = execute(resume_document, resume_state)
        results["terminal_immutable"] = {
            "new_run": second.data["run_id"] != interrupted_id,
            "prior_unchanged": (resume_state / "runs" / interrupted_id / "events.jsonl").read_bytes() == terminal_bytes,
            "verdict": second.verdict,
            "containers": remaining(second.data["run_id"]),
        }

        second_manifest = json.loads(json.dumps(resume_manifest))
        second_manifest["revision"] = 2
        second_manifest["description"] = "Different manifest digest must not resume the existing active key."
        second_path = snapshot.root / "workflow-second.json"
        second_path.write_text(json.dumps(second_manifest), encoding="utf-8")
        second_document = load_manifest(second_path)
        old_id = str(uuid.uuid4())
        old_archive = RunArchive(resume_state, old_id, resume_document, match(resume_document))
        old_archive.create()
        old_archive.append("run.queued", "queued")
        old_archive.append("run.started", "running")
        old_bytes = old_archive.events_path.read_bytes()
        _atomic_json(
            resume_state / "active" / f"{key}.json",
            {"schema_version": "incidentseal-workflow-active-pointer/v1", "active_key": key, "run_id": old_id},
        )
        distinct = execute(second_document, resume_state)
        results["different_digest"] = {
            "new_run": distinct.data["run_id"] != old_id,
            "old_nonterminal_preserved": (resume_state / "runs" / old_id / "events.jsonl").read_bytes() == old_bytes,
            "old_active_preserved": (resume_state / "active" / f"{key}.json").exists(),
            "verdict": distinct.verdict,
            "containers": remaining(distinct.data["run_id"]),
        }

        _, cancel_document, _ = create_repository(temporary, "cancel", "import time\ntime.sleep(60)\n")
        cancel_state = temporary / "cancel-state"
        cancel_digest = cancel_document.digest
        interrupted = threading.Event()

        def interrupt_when_running() -> None:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                running = run(["docker", "ps", "-q", "--filter", f"label=dev.incidentseal.manifest-digest={cancel_digest}"], ROOT)
                if running:
                    interrupted.set()
                    _thread.interrupt_main()
                    return
                time.sleep(0.05)

        interrupter = threading.Thread(target=interrupt_when_running, daemon=True)
        interrupter.start()
        cancelled = execute(cancel_document, cancel_state)
        interrupter.join(timeout=5)
        cancelled_events, cancelled_exit = read_archive_events(cancel_state, cancelled.data["run_id"])
        results["cancelled"] = {
            "interrupt_observed": interrupted.is_set(), "verdict": cancelled.verdict, "lifecycle": cancelled.lifecycle,
            "exit": cancelled.exit_code, "stream_exit": cancelled_exit, "events": len(cancelled_events),
            "containers": remaining(cancelled.data["run_id"]),
        }

        expected = {
            "failure": {"verdict": "FAIL", "lifecycle": "completed", "exit": 10, "stream_exit": 10, "events": 6, "containers": 0},
            "inconclusive": {"verdict": "INCONCLUSIVE", "lifecycle": "completed", "exit": 11, "stream_exit": 11, "events": 6, "containers": 0},
            "stale": {"verdict": None, "lifecycle": "stale", "exit": 22, "stream_exit": 22, "events": 3, "containers": 0},
            "resume": {"same_run": True, "verdict": "PASS", "lifecycle": "completed", "exit": 0, "stream_exit": 0, "events": 8, "active_removed": True, "containers": 0},
            "started_step_replay": {"crash_exit": 91, "runtime_retained_before_resume": True, "same_run": True, "verdict": "PASS", "lifecycle": "completed", "exit": 0, "stream_exit": 0, "events": 11, "containers": 0},
            "unknown_runtime": {"verdict": "INCONCLUSIVE", "lifecycle": "completed", "exit": 11, "stream_exit": 11, "events": 4, "unowned_runtime_untouched": True, "containers_after_probe_cleanup": 0},
            "terminal_immutable": {"new_run": True, "prior_unchanged": True, "verdict": "PASS", "containers": 0},
            "different_digest": {"new_run": True, "old_nonterminal_preserved": True, "old_active_preserved": True, "verdict": "PASS", "containers": 0},
            "cancelled": {"interrupt_observed": True, "verdict": None, "lifecycle": "cancelled", "exit": 20, "stream_exit": 20, "events": 5, "containers": 0},
        }
        passed = results == expected
        output = {
            "schema_version": "incidentseal-workflow-recovery-real-probe/v1",
            "verification_verdict": "PASS" if passed else "FAIL",
            "scenarios": results,
            "production_approval_written": False,
            "synthetic_temporary_authority": True,
        }
        print(json.dumps(output, separators=(",", ":"), sort_keys=True))
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
