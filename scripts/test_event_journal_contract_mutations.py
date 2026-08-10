#!/usr/bin/env python3
"""Require the frozen event journal contract to reject bounded mutations."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_event_journal_contract import (  # noqa: E402
    GENESIS,
    JournalError,
    MemoryJournal,
    digest_value,
    load,
)


def rederive(record: dict[str, Any]) -> None:
    event = record["event"]
    record["event_digest"] = digest_value(event)
    record["idempotency_key"] = digest_value(
        {
            "schema_version": "incidentseal-event-idempotency/v1",
            "run_id": event["run_id"],
            "sequence": event["sequence"],
            "event_digest": record["event_digest"],
            "previous_link_digest": record["previous_link_digest"],
        }
    )
    record["link_digest"] = digest_value(
        {
            "schema_version": "incidentseal-event-link/v1",
            "sequence": event["sequence"],
            "event_digest": record["event_digest"],
            "previous_link_digest": record["previous_link_digest"],
        }
    )


def exercise(case_id: str, cases: dict[str, list[dict[str, Any]]]) -> None:
    completed = deepcopy(cases["completed-pass"])
    stale = deepcopy(cases["stale-authority"])
    superseded = deepcopy(cases["superseded-attempt"])
    journal = MemoryJournal()

    if case_id == "unknown-record-field":
        completed[0]["unexpected"] = True
        journal.append(completed[0])
    elif case_id == "idempotency-key-drift":
        completed[0]["idempotency_key"] = "sha256:" + "1" * 64
        journal.append(completed[0])
    elif case_id == "event-digest-drift":
        completed[0]["event_digest"] = "sha256:" + "1" * 64
        journal.append(completed[0])
    elif case_id == "predecessor-drift":
        completed[0]["previous_link_digest"] = "sha256:" + "1" * 64
        event = completed[0]["event"]
        completed[0]["idempotency_key"] = digest_value(
            {
                "schema_version": "incidentseal-event-idempotency/v1",
                "run_id": event["run_id"],
                "sequence": event["sequence"],
                "event_digest": completed[0]["event_digest"],
                "previous_link_digest": completed[0]["previous_link_digest"],
            }
        )
        journal.append(completed[0])
    elif case_id == "link-digest-drift":
        completed[0]["link_digest"] = "sha256:" + "1" * 64
        journal.append(completed[0])
    elif case_id == "nonzero-first-sequence":
        completed[0]["event"]["sequence"] = 1
        rederive(completed[0])
        journal.append(completed[0])
    elif case_id == "later-sequence-gap":
        journal.append(completed[0])
        completed[1]["event"]["sequence"] = 2
        rederive(completed[1])
        journal.append(completed[1])
    elif case_id == "competing-run-sequence":
        journal.append(completed[0])
        journal.append(completed[1])
        competitor = deepcopy(completed[1])
        competitor["event"]["event_id"] = "323e4567-e89b-42d3-a456-426614174102"
        competitor["event"]["payload"] = {"host": "competing"}
        rederive(competitor)
        journal.append(competitor)
    elif case_id == "event-id-reuse":
        journal.append(completed[0])
        stale[0]["event"]["event_id"] = completed[0]["event"]["event_id"]
        rederive(stale[0])
        journal.append(stale[0])
    elif case_id == "idempotency-key-reuse":
        journal.append(completed[0])
        competitor = deepcopy(completed[0])
        competitor["event"]["payload"] = {"attempt": 99, "claim_id": "release.ready"}
        journal.append(competitor)
    elif case_id == "lifecycle-regression":
        journal.append(completed[0])
        completed[1]["event"]["event_type"] = "run.queued"
        completed[1]["event"]["lifecycle"] = "queued"
        rederive(completed[1])
        journal.append(completed[1])
    elif case_id == "append-after-terminal":
        for record in completed:
            journal.append(record)
        extra = deepcopy(completed[-1])
        extra["previous_link_digest"] = completed[-1]["link_digest"]
        extra["event"].update(
            {
                "event_id": "323e4567-e89b-42d3-a456-426614174103",
                "sequence": 3,
                "occurred_at_utc": "2026-08-09T23:50:03Z",
                "event_type": "evidence.recorded",
                "lifecycle": "running",
                "verdict": None,
                "terminal": False,
                "payload": {"late": True},
            }
        )
        rederive(extra)
        journal.append(extra)
    elif case_id == "completed-without-verdict":
        completed[-1]["event"]["verdict"] = None
        rederive(completed[-1])
        journal.append(completed[-1])
    elif case_id == "stale-authority-equal":
        event = stale[-1]["event"]
        event["payload"]["observed_authority_digest"] = event["payload"]["expected_authority_digest"]
        rederive(stale[-1])
        journal.append(stale[-1])
    elif case_id == "superseded-self-reference":
        event = superseded[-1]["event"]
        event["payload"]["superseded_by_run_id"] = event["run_id"]
        rederive(superseded[-1])
        journal.append(superseded[-1])
    elif case_id == "authority-drift-within-run":
        journal.append(completed[0])
        completed[1]["event"]["manifest_digest"] = "sha256:" + "1" * 64
        completed[1]["event"]["approval_digest"] = "sha256:" + "1" * 64
        rederive(completed[1])
        journal.append(completed[1])
    else:
        raise ValueError(f"unknown journal mutation: {case_id}")


def main() -> int:
    vectors = load(ROOT / "fixtures/journal/vectors.json")
    cases = {case["id"]: case["records"] for case in vectors["cases"]}
    manifest = load(ROOT / "fixtures/journal/mutations.json")
    baseline = MemoryJournal()
    first = deepcopy(cases["completed-pass"][0])
    inserted = baseline.append(first)
    replayed = baseline.append(deepcopy(first))
    if inserted["disposition"] != "inserted" or replayed["disposition"] != "replayed" or replayed["event_count"] != 1:
        raise RuntimeError("exact replay baseline did not remain idempotent")
    results: list[dict[str, Any]] = []
    for mutation in manifest["mutations"]:
        try:
            exercise(mutation["id"], cases)
        except JournalError as error:
            actual = error.code
        else:
            actual = None
        passed = actual == mutation["expected_error"]
        results.append(
            {
                "id": mutation["id"],
                "expected_error": mutation["expected_error"],
                "actual_error": actual,
                "verdict": "PASS" if passed else "FAIL",
            }
        )
        if not passed:
            raise RuntimeError(f"journal mutation {mutation['id']} returned {actual}")
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-event-journal-mutation-results/v1",
                "verdict": "PASS",
                "mutation_count": len(results),
                "mutations": results,
                "exact_replay": "PASS",
                "runtime_started": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
