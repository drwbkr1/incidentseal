"""Fixed repeated evaluation for the IncidentSeal evidence dashboard."""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
from typing import Any

from .dashboard_contract import EXPECTED_METRICS, EXPECTED_SCENARIOS, validate_corpus, validate_snapshot
from .dashboard_surface import (
    ASSET_ROOT,
    BIND_HOST,
    CORPUS_PATH,
    ROUTES,
    SECURITY_HEADERS,
    SNAPSHOT_PATH,
    DashboardApplication,
    DashboardServer,
    _load_fixed,
    render_dashboard,
)
from .manifest import canonical_bytes, strict_load_bytes


ROOT = Path(__file__).resolve().parents[2]
REPETITIONS = 3
SOURCE_RECORDS = 7
ROUTE_COUNT = len(ROUTES)
TRIAL_COUNT = len(EXPECTED_SCENARIOS) * REPETITIONS
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIME_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
NON_CLAIMS = (
    "Latency measures source projection and deterministic server-side HTML generation, not browser paint.",
    "Measured resource use is local process evidence, not a cross-machine performance guarantee.",
    "The evaluator cannot approve a workflow, execute one, access Docker, or create a release claim.",
    "This local candidate still requires exact credential-free public reproduction.",
)
SCOPE = {
    "projection_latency_measurement": "strict source load, validation, canonical projection, and fixed scenario selection",
    "render_latency_measurement": "deterministic server-side HTML generation",
    "browser_paint_measured": False,
    "browser_evidence_ref": "requirements/dashboard-browser.lock.json",
    "performance_budget_enforced": False,
}
SECURITY_BOUNDARY = {
    "bind_host": "127.0.0.1",
    "routes_per_trial": ROUTE_COUNT,
    "external_requests": 0,
    "write_requests": 0,
    "repository_writes": 0,
    "docker_accessed": False,
    "approval_accessed": False,
    "workflow_executed": False,
    "secrets_accessed": False,
    "telemetry_used": False,
}


class DashboardEvaluationError(ValueError):
    """Stable repeated-evaluation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise DashboardEvaluationError(code, message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _file_digest(path: Path) -> str:
    return _digest(path.read_bytes())


def _git_status(root: Path) -> str:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=root, capture_output=True, text=True,
        timeout=10, check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise DashboardEvaluationError("IS_DASHBOARD_EVALUATION_CUSTODY", "Git custody inspection failed")
    return completed.stdout


def _peak_process_memory_bytes() -> int:
    """Return dependency-free peak resident process memory in bytes."""

    if os.name == "nt":
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            _reject("IS_DASHBOARD_EVALUATION_RESOURCE", "process memory observation failed")
        return int(counters.PeakWorkingSetSize)

    import resource

    peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return peak if sys.platform == "darwin" else peak * 1024


def _request(port: int, target: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(BIND_HOST, port, timeout=4)
    try:
        connection.putrequest("GET", target, skip_host=True)
        connection.putheader("Host", f"{BIND_HOST}:{port}")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        body = response.read()
        return response.status, {name: value for name, value in response.getheaders()}, body
    finally:
        connection.close()


def _fixed_application(root: Path, scenario_id: str) -> tuple[DashboardApplication, int, int]:
    projection_start = time.perf_counter_ns()
    snapshot = strict_load_bytes(_load_fixed(root, SNAPSHOT_PATH))
    corpus = strict_load_bytes(_load_fixed(root, CORPUS_PATH))
    if not isinstance(snapshot, dict) or not isinstance(corpus, dict):
        _reject("IS_DASHBOARD_EVALUATION_INPUT", "dashboard evaluation input is not an object")
    validate_snapshot(snapshot, root)
    validate_corpus(corpus)
    scenario = next((item for item in corpus["scenarios"] if item["id"] == scenario_id), None)
    if scenario is None:
        _reject("IS_DASHBOARD_EVALUATION_INPUT", f"fixed scenario is missing: {scenario_id}")
    snapshot_bytes = canonical_bytes(snapshot)
    projection_latency_ns = max(1, time.perf_counter_ns() - projection_start)

    render_start = time.perf_counter_ns()
    html_bytes = render_dashboard(snapshot, scenario)
    render_latency_ns = max(1, time.perf_counter_ns() - render_start)
    css_bytes = _load_fixed(root, ASSET_ROOT / "dashboard.css")
    javascript_bytes = _load_fixed(root, ASSET_ROOT / "dashboard.js")
    health_bytes = canonical_bytes({
        "schema_version": "incidentseal-dashboard-health/v1",
        "status": "ready",
        "read_only": True,
        "bind_host": BIND_HOST,
        "snapshot_digest": snapshot["snapshot_digest"],
        "scenario_id": scenario["id"],
    })
    return DashboardApplication(
        snapshot=snapshot,
        scenario=scenario,
        snapshot_bytes=snapshot_bytes,
        html_bytes=html_bytes,
        css_bytes=css_bytes,
        javascript_bytes=javascript_bytes,
        health_bytes=health_bytes,
    ), projection_latency_ns, render_latency_ns


def _exercise_trial(root: Path, repetition: int, scenario_order: int, sequence: int, expected: tuple[Any, ...]) -> dict[str, Any]:
    scenario_id, kind, lifecycle, run_verdict, observation_verdict, exit_code, evidence_condition, claim_allowed, rendered_label = expected
    application, projection_latency_ns, render_latency_ns = _fixed_application(root, scenario_id)
    expected_bodies = {
        "/": application.html_bytes,
        "/assets/dashboard.css": application.css_bytes,
        "/assets/dashboard.js": application.javascript_bytes,
        "/api/snapshot": application.snapshot_bytes,
        "/healthz": application.health_bytes,
    }
    server = DashboardServer(0, application)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    request_failures = 0
    response_bytes = 0
    thread.start()
    try:
        for target in ROUTES:
            try:
                status, headers, body = _request(port, target)
                response_bytes += len(body)
                if status != 200 or body != expected_bodies[target] or int(headers.get("Content-Length", "-1")) != len(body):
                    request_failures += 1
                if any(headers.get(name) != value for name, value in SECURITY_HEADERS.items()):
                    request_failures += 1
            except Exception:
                request_failures += 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        server_closed = not thread.is_alive() and probe.connect_ex((BIND_HOST, port)) != 0

    html = application.html_bytes.decode("utf-8")
    permitted = "<strong>Claim permitted</strong>" in html
    withheld = "<strong>Claim withheld</strong>" in html
    claim_observed = "permitted" if permitted and not withheld else "withheld" if withheld and not permitted else "ambiguous"
    label_observed = rendered_label if f">{rendered_label.upper()}</strong>" in html else ""
    semantics = application.scenario
    case_correct = (
        semantics["id"] == scenario_id
        and semantics["kind"] == kind
        and semantics["lifecycle"] == lifecycle
        and semantics["run_verdict"] == run_verdict
        and semantics["observation_verdict"] == observation_verdict
        and semantics["exit_code"] == exit_code
        and semantics["evidence_condition"] == evidence_condition
        and semantics["claim_allowed"] is claim_allowed
        and label_observed == rendered_label
        and claim_observed == ("permitted" if claim_allowed else "withheld")
        and request_failures == 0
        and server_closed
    )
    return {
        "sequence": sequence,
        "repetition": repetition,
        "scenario_order": scenario_order,
        "scenario_id": scenario_id,
        "kind": kind,
        "lifecycle": lifecycle,
        "run_verdict": run_verdict,
        "observation_verdict": observation_verdict,
        "exit_code": exit_code,
        "evidence_condition": evidence_condition,
        "claim_allowed": claim_allowed,
        "claim_observed": claim_observed,
        "label_observed": label_observed,
        "case_correct": case_correct,
        "projection_latency_ns": projection_latency_ns,
        "render_latency_ns": render_latency_ns,
        "peak_process_memory_bytes": _peak_process_memory_bytes(),
        "response_bytes": response_bytes,
        "request_count": ROUTE_COUNT,
        "request_failures": request_failures,
        "source_records_verified": len(application.snapshot["source_records"]),
        "source_records_expected": SOURCE_RECORDS,
        "html_digest": _digest(application.html_bytes),
        "server_closed": server_closed,
    }


def _decimal_ratio(numerator: int, denominator: int) -> str:
    if denominator <= 0 or numerator < 0 or numerator > denominator:
        _reject("IS_DASHBOARD_EVALUATION_METRIC", "ratio inputs differ")
    scaled = numerator * 1_000_000 // denominator
    return f"{scaled // 1_000_000}.{scaled % 1_000_000:06d}"


def _milliseconds(nanoseconds: int) -> str:
    return f"{nanoseconds // 1_000_000}.{nanoseconds % 1_000_000:06d}"


def _nearest_rank(values: list[int], percentile: int) -> int:
    ordered = sorted(values)
    index = max(0, (percentile * len(ordered) + 99) // 100 - 1)
    return ordered[index]


def _integer_distribution(values: list[int], unit: str) -> dict[str, Any]:
    ordered = sorted(values)
    return {
        "unit": unit,
        "count": len(ordered),
        "minimum": ordered[0],
        "median": ordered[len(ordered) // 2],
        "p95_nearest_rank": _nearest_rank(ordered, 95),
        "maximum": ordered[-1],
    }


def _latency_distribution(values: list[int]) -> dict[str, Any]:
    raw = _integer_distribution(values, "nanoseconds")
    return {
        "unit": "milliseconds",
        "count": raw["count"],
        "minimum": _milliseconds(raw["minimum"]),
        "median": _milliseconds(raw["median"]),
        "p95_nearest_rank": _milliseconds(raw["p95_nearest_rank"]),
        "maximum": _milliseconds(raw["maximum"]),
        "raw_unit": "nanoseconds",
    }


def _scenario_summaries(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = []
    for expected in EXPECTED_SCENARIOS:
        selected = [trial for trial in trials if trial["scenario_id"] == expected[0]]
        summaries.append({
            "scenario_id": expected[0],
            "trials": len(selected),
            "correct": sum(1 for trial in selected if trial["case_correct"] is True),
            "stable_html_digest": len({trial["html_digest"] for trial in selected}) == 1,
            "html_digest": selected[0]["html_digest"],
            "projection_latency_ms": _latency_distribution([trial["projection_latency_ns"] for trial in selected]),
            "render_latency_ms": _latency_distribution([trial["render_latency_ns"] for trial in selected]),
        })
    return summaries


def _metrics(trials: list[dict[str, Any]]) -> dict[str, Any]:
    correct = sum(1 for trial in trials if trial["case_correct"] is True)
    source_verified = sum(trial["source_records_verified"] for trial in trials)
    source_expected = sum(trial["source_records_expected"] for trial in trials)
    permitted = sum(1 for trial in trials if trial["claim_observed"] == "permitted")
    withheld = sum(1 for trial in trials if trial["claim_observed"] == "withheld")
    false_passes = sum(1 for trial in trials if trial["kind"] != "success" and trial["claim_observed"] == "permitted")
    false_release_claims = sum(1 for trial in trials if not trial["claim_allowed"] and trial["claim_observed"] == "permitted")
    calibrated = sum(1 for trial in trials if trial["claim_observed"] == ("permitted" if trial["claim_allowed"] else "withheld"))
    return {
        "case_correctness": {"correct": correct, "total": len(trials), "ratio": _decimal_ratio(correct, len(trials))},
        "projection_latency_ms": _latency_distribution([trial["projection_latency_ns"] for trial in trials]),
        "render_latency_ms": _latency_distribution([trial["render_latency_ns"] for trial in trials]),
        "peak_process_memory_bytes": _integer_distribution([trial["peak_process_memory_bytes"] for trial in trials], "bytes"),
        "response_bytes": _integer_distribution([trial["response_bytes"] for trial in trials], "bytes_per_five_gets"),
        "request_failures": {"count": sum(trial["request_failures"] for trial in trials), "requests": len(trials) * ROUTE_COUNT},
        "source_record_coverage": {"verified": source_verified, "expected": source_expected, "ratio": _decimal_ratio(source_verified, source_expected)},
        "claim_calibration": {
            "calibrated": calibrated,
            "total": len(trials),
            "ratio": _decimal_ratio(calibrated, len(trials)),
            "claims_permitted": permitted,
            "claims_withheld": withheld,
            "false_passes": false_passes,
            "false_release_claims": false_release_claims,
        },
    }


def _recovery(trials: list[dict[str, Any]]) -> dict[str, Any]:
    transitions = 0
    for repetition in range(1, REPETITIONS + 1):
        selected = [trial for trial in trials if trial["repetition"] == repetition]
        crash = selected[7]
        recovery = selected[8]
        if (
            crash["kind"] == "crash" and crash["lifecycle"] == "failed" and crash["run_verdict"] is None
            and crash["claim_observed"] == "withheld" and recovery["kind"] == "recovery"
            and recovery["lifecycle"] == "completed" and recovery["observation_verdict"] == "PASS"
            and recovery["run_verdict"] is None and recovery["claim_observed"] == "withheld"
        ):
            transitions += 1
    return {
        "crash_recovery_transitions": transitions,
        "expected": REPETITIONS,
        "all_recovered_without_claim_promotion": transitions == REPETITIONS,
    }


def _completeness(trials: list[dict[str, Any]]) -> dict[str, Any]:
    present = [
        "case_correctness",
        "projection_latency_ms",
        "render_latency_ms",
        "peak_process_memory_bytes",
        "response_bytes",
        "request_failures",
        "source_record_coverage",
        "claim_calibration",
    ]
    return {
        "required_metrics": len(EXPECTED_METRICS),
        "reported_metrics": len(present),
        "metric_names_exact": tuple(EXPECTED_METRICS) == tuple(present),
        "trial_records": len(trials),
        "expected_trial_records": TRIAL_COUNT,
        "all_trials_complete": len(trials) == TRIAL_COUNT,
    }


def run_evaluation(evaluation_lock_digest: str, root: Path = ROOT) -> dict[str, Any]:
    """Run the fixed nine-case corpus three times through real loopback responses."""

    if SHA_RE.fullmatch(evaluation_lock_digest) is None:
        _reject("IS_DASHBOARD_EVALUATION_IDENTITY", "evaluation lock digest differs")
    before_status = _git_status(root)
    trials = []
    sequence = 0
    for repetition in range(1, REPETITIONS + 1):
        for scenario_order, expected in enumerate(EXPECTED_SCENARIOS, 1):
            sequence += 1
            trials.append(_exercise_trial(root, repetition, scenario_order, sequence, expected))
    after_status = _git_status(root)
    metrics = _metrics(trials)
    recovery = _recovery(trials)
    runtime_boundary = {
        "servers_started": TRIAL_COUNT,
        "servers_closed": sum(1 for trial in trials if trial["server_closed"] is True),
        "server_processes_after": 0 if all(trial["server_closed"] is True for trial in trials) else 1,
        "repository_state_unchanged": before_status == after_status,
    }
    passed = (
        metrics["case_correctness"]["correct"] == TRIAL_COUNT
        and metrics["request_failures"]["count"] == 0
        and metrics["source_record_coverage"]["verified"] == metrics["source_record_coverage"]["expected"]
        and metrics["claim_calibration"]["false_passes"] == 0
        and metrics["claim_calibration"]["false_release_claims"] == 0
        and recovery["all_recovered_without_claim_promotion"] is True
        and runtime_boundary["server_processes_after"] == 0
        and runtime_boundary["repository_state_unchanged"] is True
    )
    result = {
        "schema_version": "incidentseal-dashboard-repeated-evaluation/v1",
        "evaluation_id": "IS-EVAL-0005-U04-REPEATED",
        "checkpoint_id": "IS-0005",
        "unit_id": "IS5-U04",
        "observed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "execution_state": "completed",
        "verification_verdict": "PASS" if passed else "FAIL",
        "identity": {
            "evaluation_lock_digest": evaluation_lock_digest,
            "contract_lock_digest": _file_digest(root / "requirements" / "dashboard-contract.lock.json"),
            "implementation_lock_digest": _file_digest(root / "requirements" / "dashboard-implementation.lock.json"),
            "browser_lock_digest": _file_digest(root / "requirements" / "dashboard-browser.lock.json"),
            "snapshot_digest": "sha256:fc438a90a18ff2117db59ab781052934236c1a49ac313837ac4bcb83c54c89b2",
            "corpus_digest": "sha256:76bf8d4e5aa9b080f87a4eefb4c1c91ce1b22d6ba1c1d3b5dab23890fc455560",
        },
        "plan": {
            "scenarios": len(EXPECTED_SCENARIOS),
            "repetitions": REPETITIONS,
            "trials": TRIAL_COUNT,
            "routes_per_trial": ROUTE_COUNT,
            "metrics": list(EXPECTED_METRICS),
        },
        "trials": trials,
        "scenario_summaries": _scenario_summaries(trials),
        "metrics": metrics,
        "recovery": recovery,
        "evidence_completeness": _completeness(trials),
        "security_boundary": dict(SECURITY_BOUNDARY),
        "runtime_boundary": runtime_boundary,
        "scope": dict(SCOPE),
        "runtime_dependencies": [],
        "non_claims": list(NON_CLAIMS),
    }
    validate_result(result, evaluation_lock_digest=evaluation_lock_digest, root=root)
    return result


def _exact(value: Any, fields: set[str], code: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject(code, f"{label} fields differ")
    return value


def _positive_integer(value: Any, code: str, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _reject(code, f"{label} differs")
    return value


def validate_result(value: Any, *, evaluation_lock_digest: str, root: Path = ROOT) -> dict[str, Any]:
    """Fail closed on incomplete, state-collapsed, or authority-broadening results."""

    result = _exact(value, {
        "schema_version", "evaluation_id", "checkpoint_id", "unit_id", "observed_at_utc",
        "execution_state", "verification_verdict", "identity", "plan", "trials",
        "scenario_summaries", "metrics", "recovery", "evidence_completeness",
        "security_boundary", "runtime_boundary", "scope", "runtime_dependencies", "non_claims",
    }, "IS_DASHBOARD_EVALUATION_SCHEMA", "evaluation")
    if (
        result["schema_version"] != "incidentseal-dashboard-repeated-evaluation/v1"
        or result["evaluation_id"] != "IS-EVAL-0005-U04-REPEATED"
        or result["checkpoint_id"] != "IS-0005"
        or result["unit_id"] != "IS5-U04"
        or result["execution_state"] != "completed"
        or not isinstance(result["observed_at_utc"], str)
        or TIME_RE.fullmatch(result["observed_at_utc"]) is None
    ):
        _reject("IS_DASHBOARD_EVALUATION_SCHEMA", "evaluation envelope differs")
    identity = _exact(result["identity"], {
        "evaluation_lock_digest", "contract_lock_digest", "implementation_lock_digest",
        "browser_lock_digest", "snapshot_digest", "corpus_digest",
    }, "IS_DASHBOARD_EVALUATION_IDENTITY", "identity")
    expected_identity = {
        "evaluation_lock_digest": evaluation_lock_digest,
        "contract_lock_digest": _file_digest(root / "requirements" / "dashboard-contract.lock.json"),
        "implementation_lock_digest": _file_digest(root / "requirements" / "dashboard-implementation.lock.json"),
        "browser_lock_digest": _file_digest(root / "requirements" / "dashboard-browser.lock.json"),
        "snapshot_digest": "sha256:fc438a90a18ff2117db59ab781052934236c1a49ac313837ac4bcb83c54c89b2",
        "corpus_digest": "sha256:76bf8d4e5aa9b080f87a4eefb4c1c91ce1b22d6ba1c1d3b5dab23890fc455560",
    }
    if identity != expected_identity:
        _reject("IS_DASHBOARD_EVALUATION_IDENTITY", "evaluation identity differs")
    if result["plan"] != {
        "scenarios": len(EXPECTED_SCENARIOS), "repetitions": REPETITIONS,
        "trials": TRIAL_COUNT, "routes_per_trial": ROUTE_COUNT, "metrics": list(EXPECTED_METRICS),
    }:
        _reject("IS_DASHBOARD_EVALUATION_PLAN", "evaluation plan differs")

    trials = result["trials"]
    if not isinstance(trials, list) or len(trials) != TRIAL_COUNT:
        _reject("IS_DASHBOARD_EVALUATION_TRIAL", "trial count differs")
    trial_fields = {
        "sequence", "repetition", "scenario_order", "scenario_id", "kind", "lifecycle",
        "run_verdict", "observation_verdict", "exit_code", "evidence_condition", "claim_allowed",
        "claim_observed", "label_observed", "case_correct", "projection_latency_ns",
        "render_latency_ns", "peak_process_memory_bytes", "response_bytes", "request_count",
        "request_failures", "source_records_verified", "source_records_expected", "html_digest",
        "server_closed",
    }
    for index, trial in enumerate(trials):
        item = _exact(trial, trial_fields, "IS_DASHBOARD_EVALUATION_TRIAL", "trial")
        repetition = index // len(EXPECTED_SCENARIOS) + 1
        order = index % len(EXPECTED_SCENARIOS) + 1
        expected = EXPECTED_SCENARIOS[order - 1]
        observed = (
            item["scenario_id"], item["kind"], item["lifecycle"], item["run_verdict"],
            item["observation_verdict"], item["exit_code"], item["evidence_condition"],
            item["claim_allowed"], item["label_observed"],
        )
        if item["sequence"] != index + 1 or item["repetition"] != repetition or item["scenario_order"] != order or observed != expected:
            _reject("IS_DASHBOARD_EVALUATION_TRIAL", "trial order or semantics differ")
        expected_claim = "permitted" if expected[7] else "withheld"
        if item["claim_observed"] != expected_claim:
            _reject("IS_DASHBOARD_EVALUATION_CALIBRATION", "trial claim calibration differs")
        if item["case_correct"] is not True:
            _reject("IS_DASHBOARD_EVALUATION_CORRECTNESS", "trial correctness differs")
        for field in ("projection_latency_ns", "render_latency_ns", "peak_process_memory_bytes", "response_bytes", "request_count"):
            _positive_integer(item[field], "IS_DASHBOARD_EVALUATION_METRIC", field)
        if item["request_count"] != ROUTE_COUNT or item["request_failures"] != 0:
            _reject("IS_DASHBOARD_EVALUATION_REQUEST", "trial request evidence differs")
        if item["source_records_verified"] != SOURCE_RECORDS or item["source_records_expected"] != SOURCE_RECORDS:
            _reject("IS_DASHBOARD_EVALUATION_EVIDENCE", "trial source coverage differs")
        if not isinstance(item["html_digest"], str) or SHA_RE.fullmatch(item["html_digest"]) is None:
            _reject("IS_DASHBOARD_EVALUATION_DETERMINISM", "trial HTML identity differs")
        if item["server_closed"] is not True:
            _reject("IS_DASHBOARD_EVALUATION_RUNTIME", "trial server remained")

    expected_summaries = _scenario_summaries(trials)
    if result["scenario_summaries"] != expected_summaries or any(not item["stable_html_digest"] for item in expected_summaries):
        _reject("IS_DASHBOARD_EVALUATION_DETERMINISM", "scenario summary or HTML stability differs")
    expected_metrics = _metrics(trials)
    if result["metrics"] != expected_metrics:
        _reject("IS_DASHBOARD_EVALUATION_METRIC", "aggregate metrics differ")
    if expected_metrics["claim_calibration"]["false_passes"] or expected_metrics["claim_calibration"]["false_release_claims"]:
        _reject("IS_DASHBOARD_EVALUATION_CALIBRATION", "false claim observed")
    expected_recovery = _recovery(trials)
    if result["recovery"] != expected_recovery or expected_recovery["all_recovered_without_claim_promotion"] is not True:
        _reject("IS_DASHBOARD_EVALUATION_RECOVERY", "recovery transition differs")
    if result["evidence_completeness"] != _completeness(trials) or result["evidence_completeness"]["metric_names_exact"] is not True:
        _reject("IS_DASHBOARD_EVALUATION_EVIDENCE", "evaluation completeness differs")
    if result["security_boundary"] != SECURITY_BOUNDARY:
        _reject("IS_DASHBOARD_EVALUATION_SECURITY", "evaluation security boundary differs")
    runtime = _exact(result["runtime_boundary"], {
        "servers_started", "servers_closed", "server_processes_after", "repository_state_unchanged",
    }, "IS_DASHBOARD_EVALUATION_RUNTIME", "runtime boundary")
    if runtime != {
        "servers_started": TRIAL_COUNT, "servers_closed": TRIAL_COUNT,
        "server_processes_after": 0, "repository_state_unchanged": True,
    }:
        _reject("IS_DASHBOARD_EVALUATION_RUNTIME", "evaluation teardown differs")
    if result["scope"] != SCOPE:
        _reject("IS_DASHBOARD_EVALUATION_SCOPE", "evaluation measurement scope differs")
    if result["runtime_dependencies"] != []:
        _reject("IS_DASHBOARD_EVALUATION_DEPENDENCY", "evaluation gained a runtime dependency")
    if tuple(result["non_claims"]) != NON_CLAIMS:
        _reject("IS_DASHBOARD_EVALUATION_SCOPE", "evaluation non-claims differ")
    if result["verification_verdict"] != "PASS":
        _reject("IS_DASHBOARD_EVALUATION_VERDICT", "passing evidence did not retain PASS")
    return result
