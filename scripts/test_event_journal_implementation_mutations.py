#!/usr/bin/env python3
"""Require security-relevant journal implementation mutations to fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
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


MUTATIONS = (
    Mutation(
        "remove-per-run-transaction-lock",
        "containers/migration/001-schema.sql",
        "PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_run_id::text, 0));",
        "PERFORM 1;",
    ),
    Mutation(
        "security-definer-removed",
        "containers/migration/001-schema.sql",
        "LANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\nAS $incidentseal$",
        "LANGUAGE plpgsql\nSECURITY INVOKER\nSET search_path = pg_catalog, public\nAS $incidentseal$",
    ),
    Mutation(
        "security-definer-search-path-broadened",
        "containers/migration/001-schema.sql",
        "SECURITY DEFINER\nSET search_path = pg_catalog, public",
        "SECURITY DEFINER\nSET search_path = public, pg_catalog",
    ),
    Mutation(
        "public-append-execution",
        "containers/migration/001-schema.sql",
        "REVOKE ALL ON FUNCTION public.incidentseal_append_event(bytea, bytea) FROM PUBLIC;",
        "GRANT EXECUTE ON FUNCTION public.incidentseal_append_event(bytea, bytea) TO PUBLIC;",
    ),
    Mutation(
        "update-delete-trigger-removed",
        "containers/migration/001-schema.sql",
        "BEFORE UPDATE OR DELETE ON public.incidentseal_run_events",
        "AFTER UPDATE OR DELETE ON public.incidentseal_run_events",
    ),
    Mutation(
        "stream-reformats-jsonb",
        "src/incidentseal/journal_surface.py",
        "SELECT encode(event_bytes,'hex')",
        "SELECT encode(convert_to(event_type,'UTF8'),'hex')",
    ),
    Mutation(
        "agent-append-command-added",
        "src/incidentseal/cli.py",
        '("topology", "journal-probe"): "topology.journal-probe",',
        '("topology", "journal-probe"): "topology.journal-probe",\n    ("run", "append"): "run.append",',
    ),
    Mutation(
        "stale-implementation-lock",
        "containers/migration/001-schema.sql",
        "record_bytes bytea NOT NULL",
        "record_bytes bytea NULL",
        refresh_lock=False,
    ),
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_root(destination: Path) -> None:
    shutil.copytree(ROOT / "src", destination / "src")
    implementation = json.loads((ROOT / "requirements" / "event-journal-implementation.lock.json").read_text(encoding="utf-8"))
    contract = json.loads((ROOT / "requirements" / "event-journal-contract.lock.json").read_text(encoding="utf-8"))
    paths = {entry["path"] for entry in implementation["files"]} | {entry["path"] for entry in contract["files"]}
    paths.add("requirements/event-journal-implementation.lock.json")
    for relative in sorted(paths):
        if relative.startswith("src/"):
            continue
        copy_file(ROOT / relative, destination / relative)


def refresh_lock(root: Path, relative: str) -> None:
    lock_path = root / "requirements" / "event-journal-implementation.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entry = next(item for item in lock["files"] if item["path"] == relative)
    entry["sha256"] = digest(root / relative)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")


def invoke(root: Path) -> tuple[int, dict[str, object], str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-B", str(root / "scripts" / "validate_event_journal_implementation.py")],
        cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=90, check=False,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"implementation validator did not return JSON: {completed.stdout!r}") from error
    return completed.returncode, value, completed.stderr


def main() -> int:
    results: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-journal-mutations-") as temporary:
        base = Path(temporary) / "base"
        copy_root(base)
        baseline_code, baseline, baseline_stderr = invoke(base)
        if baseline_code != 0 or baseline.get("verdict") != "PASS" or baseline_stderr:
            raise RuntimeError(f"journal mutation baseline failed: {baseline}; stderr={baseline_stderr}")
        for index, mutation in enumerate(MUTATIONS):
            case = Path(temporary) / f"case-{index:02d}"
            shutil.copytree(base, case)
            path = case / mutation.path
            value = path.read_text(encoding="utf-8")
            if mutation.old not in value:
                raise RuntimeError(f"mutation anchor is absent: {mutation.id}")
            path.write_text(value.replace(mutation.old, mutation.new, 1), encoding="utf-8", newline="\n")
            if mutation.refresh_lock:
                refresh_lock(case, mutation.path)
            code, output, stderr = invoke(case)
            error = output.get("error", {}) if isinstance(output, dict) else {}
            passed = code != 0 and output.get("verdict") == "INVALID" and isinstance(error, dict) and error.get("code") == "IS_JOURNAL_IMPLEMENTATION" and not stderr
            results.append({"id": mutation.id, "verdict": "PASS" if passed else "FAIL"})
            if not passed:
                raise RuntimeError(f"mutation did not fail closed: {mutation.id}: {output}; stderr={stderr}")
    print(json.dumps({
        "schema_version": "incidentseal-event-journal-implementation-mutations/v1",
        "verdict": "PASS",
        "mutations": results,
        "runtime_started": False,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
