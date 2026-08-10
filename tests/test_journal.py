from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.journal import (  # noqa: E402
    JournalError,
    canonical_record,
    event_from_canonical_bytes,
    lifecycle_exit,
    validate_implementation_lock,
    validate_record,
)
from incidentseal.manifest import canonical_bytes, strict_load_bytes  # noqa: E402


class JournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = strict_load_bytes((ROOT / "fixtures" / "journal" / "vectors.json").read_bytes())

    def test_frozen_vectors_validate_to_exact_canonical_bytes(self) -> None:
        records = [record for case in self.vectors["cases"] for record in case["records"]]
        for record in records:
            validated, raw = canonical_record(record)
            self.assertEqual(record, validated)
            self.assertEqual(canonical_bytes(record), raw)
        self.assertEqual(7, len(records))

    def test_event_digest_drift_fails_closed(self) -> None:
        record = deepcopy(self.vectors["cases"][0]["records"][0])
        record["event"]["payload"]["attempt"] = 99
        with self.assertRaisesRegex(JournalError, "event digest differs") as raised:
            validate_record(record)
        self.assertEqual("IS_JOURNAL_EVENT_DIGEST", raised.exception.code)

    def test_retained_event_must_be_canonical_and_ordered(self) -> None:
        event = self.vectors["cases"][0]["records"][1]["event"]
        raw = canonical_bytes(event)
        self.assertEqual(event, event_from_canonical_bytes(raw, run_id=event["run_id"], sequence=1))
        pretty = json.dumps(event, indent=2).encode("utf-8")
        with self.assertRaises(JournalError) as raised:
            event_from_canonical_bytes(pretty, run_id=event["run_id"], sequence=1)
        self.assertEqual("IS_JOURNAL_DATABASE", raised.exception.code)

    def test_lifecycle_exit_codes_remain_distinct(self) -> None:
        expected = {"completed-pass": 0, "stale-authority": 22, "superseded-attempt": 23}
        for case in self.vectors["cases"]:
            self.assertEqual(expected[case["id"]], lifecycle_exit(case["records"][-1]["event"]))
        failed = deepcopy(self.vectors["cases"][0]["records"][-1]["event"])
        failed.update({"lifecycle": "failed", "event_type": "run.failed", "verdict": None})
        self.assertEqual(21, lifecycle_exit(failed))
        cancelled = deepcopy(failed)
        cancelled.update({"lifecycle": "cancelled", "event_type": "run.cancelled"})
        self.assertEqual(20, lifecycle_exit(cancelled))

    def test_implementation_lock_binds_runtime_surface(self) -> None:
        self.assertRegex(validate_implementation_lock(), r"^sha256:[0-9a-f]{64}$")

    def test_sql_denies_mutation_and_public_execution(self) -> None:
        sql = (ROOT / "containers" / "migration" / "001-schema.sql").read_text(encoding="utf-8")
        required = (
            "pg_advisory_xact_lock",
            "SECURITY DEFINER",
            "SET search_path = pg_catalog, public",
            "IS_JOURNAL_IMMUTABLE",
            "BEFORE UPDATE OR DELETE",
            "BEFORE TRUNCATE",
            "REVOKE ALL ON FUNCTION public.incidentseal_append_event(bytea, bytea) FROM PUBLIC",
        )
        for fragment in required:
            self.assertIn(fragment, sql)
        self.assertNotIn("GRANT UPDATE ON TABLE incidentseal_run_events", sql)
        self.assertNotIn("GRANT DELETE ON TABLE incidentseal_run_events", sql)

    def test_agent_cli_exposes_read_but_not_append(self) -> None:
        cli = (ROOT / "src" / "incidentseal" / "cli.py").read_text(encoding="utf-8")
        self.assertIn('(\"topology\", \"journal-probe\")', cli)
        self.assertIn('(\"run\", \"events\")', cli)
        self.assertNotIn('(\"run\", \"append\")', cli)

    def test_jsonl_usage_failure_does_not_emit_stdout(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "incidentseal", "run", "events", "--run-id", "not-a-uuid", "--jsonl"],
            cwd=ROOT,
            env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        self.assertEqual(64, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn("IS_JOURNAL_SCHEMA", completed.stderr)


if __name__ == "__main__":
    unittest.main()
