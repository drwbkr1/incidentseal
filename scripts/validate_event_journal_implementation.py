#!/usr/bin/env python3
"""Validate the locked durable journal implementation without starting runtime."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.journal import validate_implementation_lock  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def container_ids(docker: str | None) -> tuple[str, ...]:
    if docker is None:
        return ()
    completed = subprocess.run(
        [docker, "ps", "-aq"], cwd=ROOT, text=True, encoding="utf-8",
        capture_output=True, timeout=30, check=False,
    )
    require(completed.returncode == 0, "Docker history could not be observed")
    return tuple(completed.stdout.splitlines())


def main() -> int:
    docker = shutil.which("docker")
    before = container_ids(docker)
    lock_digest = validate_implementation_lock()
    sql = (ROOT / "containers" / "migration" / "001-schema.sql").read_text(encoding="utf-8")
    surface = (ROOT / "src" / "incidentseal" / "journal_surface.py").read_text(encoding="utf-8")
    cli = (ROOT / "src" / "incidentseal" / "cli.py").read_text(encoding="utf-8")
    for fragment in (
        "CREATE TABLE IF NOT EXISTS incidentseal_run_events",
        "PRIMARY KEY (run_id, sequence)",
        "UNIQUE (event_id)",
        "UNIQUE (idempotency_key)",
        "pg_advisory_xact_lock",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, public",
        "BEFORE UPDATE OR DELETE",
        "BEFORE TRUNCATE",
        "IS_JOURNAL_IMMUTABLE",
        "IS_JOURNAL_CONFLICT",
        "IS_JOURNAL_TERMINAL",
        "IS_JOURNAL_AUTHORITY",
        "REVOKE ALL ON TABLE incidentseal_run_events FROM PUBLIC",
        "REVOKE ALL ON FUNCTION public.incidentseal_append_event(bytea, bytea) FROM PUBLIC",
    ):
        require(fragment in sql, f"required SQL journal boundary is absent: {fragment}")
    require(
        sql.count("PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_run_id::text, 0));") == 1,
        "journal per-run advisory-lock count differs",
    )
    for forbidden in (
        "GRANT UPDATE ON TABLE incidentseal_run_events",
        "GRANT DELETE ON TABLE incidentseal_run_events",
        "GRANT ALL PRIVILEGES ON TABLE incidentseal_run_events",
        "GRANT EXECUTE ON FUNCTION public.incidentseal_append_event",
    ):
        require(forbidden not in sql, f"forbidden SQL journal authority is present: {forbidden}")
    append_start = sql.index("CREATE OR REPLACE FUNCTION public.incidentseal_append_event")
    append_end = sql.index("CREATE OR REPLACE FUNCTION public.incidentseal_acquire_recovery_fence", append_start)
    append_sql = sql[append_start:append_end]
    require(sql.count("SET search_path = pg_catalog, public") == 4, "journal and recovery function search-path count differs")
    require(
        append_sql.count("LANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\nAS $incidentseal$") == 1,
        "append function does not bind its SECURITY DEFINER search path",
    )
    for fragment in (
        "SELECT encode(event_bytes,'hex')",
        "ORDER BY sequence",
        "event_from_canonical_bytes",
        "value.get(\"Image\") != database_lock.get(\"image_id\")",
        "protected_before == protected_after",
        '"down", "--volumes", "--remove-orphans"',
        '"approval_accessed": False',
        '"workflow_executed": False',
    ):
        require(fragment in surface, f"required host journal boundary is absent: {fragment}")
    require('(\"run\", \"events\")' in cli, "run.events dispatch is absent")
    require('(\"run\", \"append\")' not in cli, "agent-facing append command is forbidden")

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    contract = subprocess.run(
        [sys.executable, "-B", str(ROOT / "scripts" / "validate_event_journal_contract.py")],
        cwd=ROOT, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(contract.returncode == 0 and json.loads(contract.stdout).get("verdict") == "PASS" and not contract.stderr, "frozen journal contract regressed")
    tests = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "tests.test_journal"],
        cwd=ROOT, env=environment, text=True, encoding="utf-8", capture_output=True, timeout=60, check=False,
    )
    require(tests.returncode == 0, f"journal unit tests failed: {tests.stdout}{tests.stderr}")
    after = container_ids(docker)
    require(before == after, "static journal validation changed Docker container history")
    print(json.dumps({
        "schema_version": "incidentseal-event-journal-implementation-validation/v1",
        "verdict": "PASS",
        "implementation_lock_digest": lock_digest,
        "contract_verdict": "PASS",
        "unit_tests": 8,
        "database_started": False,
        "runtime_started": False,
        "container_history_unchanged": True,
        "agent_append_surface": False,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-event-journal-implementation-validation/v1",
            "verdict": "INVALID",
            "error": {"code": "IS_JOURNAL_IMPLEMENTATION", "message": str(error)},
            "runtime_started": False,
        }, separators=(",", ":"), sort_keys=True))
        sys.exit(1)
