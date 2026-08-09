#!/usr/bin/env python3
"""Require the frozen portable receipt contract to reject bounded mutations."""

from __future__ import annotations

from copy import deepcopy
import json
import sys

from validate_machine_contracts import strict_load
from validate_receipt_contract import (
    FIXTURES,
    ReceiptContractError,
    load_schema_documents,
    validate_receipt,
    validate_schema_documents,
    validate_verification_report,
)


def mutate(case_id: str, receipt: dict) -> None:
    links = receipt["event_chain"]["links"]
    if case_id == "unknown-top-level-field":
        receipt["unexpected"] = True
    elif case_id == "authority-mode-smuggling":
        receipt["authority"]["mode"] = "approved-workflow"
    elif case_id == "authority-digest-drift":
        links[1]["event"]["authority_digest"] = "sha256:" + "1" * 64
    elif case_id == "duplicate-binding":
        receipt["bindings"].append(deepcopy(receipt["bindings"][0]))
    elif case_id == "event-reordering":
        links[0], links[1] = links[1], links[0]
    elif case_id == "event-truncation":
        links.pop()
    elif case_id == "event-digest-corruption":
        links[1]["event_digest"] = "sha256:" + "2" * 64
    elif case_id == "link-predecessor-corruption":
        links[1]["previous_link_digest"] = "sha256:" + "3" * 64
    elif case_id == "root-digest-corruption":
        receipt["event_chain"]["root_digest"] = "sha256:" + "4" * 64
    elif case_id == "run-summary-collapse":
        receipt["run"]["lifecycle"] = "failed"
    elif case_id == "terminal-event-drift":
        receipt["run"]["terminal_event_id"] = links[0]["event"]["event_id"]
    elif case_id == "artifact-digest-corruption":
        receipt["artifacts"][0]["digest"] = "sha256:" + "5" * 64
    elif case_id == "unsafe-artifact-path":
        receipt["artifacts"][0]["path"] = "../result.json"
    else:
        raise ValueError(f"unknown receipt mutation: {case_id}")


def main() -> int:
    try:
        documents = load_schema_documents()
        validate_schema_documents(documents)
        baseline = strict_load(FIXTURES / "receipt.valid.json")
        validate_receipt(baseline, documents, bundle_root=FIXTURES)
        manifest = strict_load(FIXTURES / "mutations.json")
        results = []
        for item in manifest["mutations"]:
            case_id = item["id"]
            expected = item["expected_error"]
            try:
                if case_id == "unbound-pass":
                    report = strict_load(FIXTURES / "verification.invalid.unbound-pass.json")
                    validate_verification_report(report, documents)
                else:
                    candidate = deepcopy(baseline)
                    mutate(case_id, candidate)
                    validate_receipt(candidate, documents, bundle_root=FIXTURES)
            except ReceiptContractError as error:
                actual = error.code
            else:
                raise RuntimeError(f"mutation {case_id} unexpectedly passed")
            status = "PASS" if actual == expected else "FAIL"
            results.append(
                {"id": case_id, "expected_error": expected, "actual_error": actual, "verdict": status}
            )
            if status != "PASS":
                raise RuntimeError(f"mutation {case_id} returned {actual}, expected {expected}")
        if len(results) != len(manifest["mutations"]):
            raise RuntimeError("mutation result count differs from the frozen manifest")
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-receipt-mutation-results/v1",
                    "verdict": "PASS",
                    "mutations": results,
                    "third_party_dependencies": 0,
                    "runtime_started": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-receipt-mutation-results/v1",
                    "verdict": "INVALID",
                    "error": {"code": "IS_RECEIPT_MUTATION", "message": str(error)},
                    "runtime_started": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
