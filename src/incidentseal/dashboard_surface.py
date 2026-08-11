"""Dependency-free, loopback-only, read-only IncidentSeal evidence dashboard."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
from typing import Any
from urllib.parse import urlsplit

from .dashboard_contract import validate_corpus, validate_snapshot
from .manifest import canonical_bytes, strict_load_bytes


BIND_HOST = "127.0.0.1"
SNAPSHOT_PATH = Path("fixtures/dashboard/snapshot.valid.json")
CORPUS_PATH = Path("fixtures/dashboard/scenario-corpus.valid.json")
ASSET_ROOT = Path("src/incidentseal/dashboard_assets")
ROUTES = ("/", "/assets/dashboard.css", "/assets/dashboard.js", "/api/snapshot", "/healthz")
ALLOWED_METHODS = ("GET", "HEAD")
SECURITY_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; "
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'; object-src 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class DashboardSurfaceError(ValueError):
    """Stable dashboard implementation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DashboardApplication:
    """Immutable in-memory projection and fixed repository-controlled assets."""

    snapshot: dict[str, Any]
    scenario: dict[str, Any]
    snapshot_bytes: bytes
    html_bytes: bytes
    css_bytes: bytes
    javascript_bytes: bytes
    health_bytes: bytes


def _load_fixed(root: Path, relative: Path) -> bytes:
    root_resolved = root.resolve()
    path = (root_resolved / relative).resolve()
    if root_resolved not in path.parents or not path.is_file() or path.is_symlink():
        raise DashboardSurfaceError("IS_DASHBOARD_ASSET", f"fixed dashboard file is unavailable: {relative.as_posix()}")
    return path.read_bytes()


def _short(value: str, count: int = 12) -> str:
    return value[:count]


def _state_row(label: str, count: int, tone: str) -> str:
    return (
        f'<li class="state-row" data-state="{escape(label)}">'
        f'<span class="state-mark state-mark--{tone}" aria-hidden="true"></span>'
        f'<span class="state-label">{escape(label)}</span>'
        f'<strong class="state-count">{count}</strong></li>'
    )


def render_dashboard(snapshot: dict[str, Any], scenario: dict[str, Any]) -> bytes:
    """Render the exact projection into a deterministic semantic HTML document."""

    source = snapshot["source"]
    states = snapshot["states"]
    scenario_copy = {
        "success": ("Evidence before claims.", "Exact evidence supports this checkpoint view.", "pass"),
        "product-failure": ("A completed run can still fail.", "Completion and product verdict remain separate.", "fail"),
        "invalid-input": ("Invalid input is not evidence.", "Rejected input cannot produce a verification claim.", "invalid"),
        "missing-evidence": ("Missing evidence stops the claim.", "A successful run cannot fill an absent receipt.", "warn"),
        "policy-attack": ("Policy changes need authority.", "The dashboard rejects attempts to rewrite its verification policy.", "invalid"),
        "isolation-attack": ("Isolation is not negotiable.", "A broader bind or write path is rejected before serving.", "invalid"),
        "corrupt-receipt": ("Corruption stays a failure.", "A passing run cannot promote mismatched receipt bytes.", "fail"),
        "crash": ("A crash is lifecycle, not verdict.", "Interrupted execution does not fabricate a product result.", "warn"),
        "recovery": ("Recovery resumes evidence, not trust.", "Recovered custody is shown without creating release authority.", "info"),
    }
    hero_title, hero_lede, scenario_tone = scenario_copy[scenario["kind"]]
    lifecycle = scenario["lifecycle"] or "none"
    run_verdict = scenario["run_verdict"] or "none"
    observation_verdict = scenario["observation_verdict"] or "none"
    claim_text = "Claim permitted" if scenario["claim_allowed"] else "Claim withheld"
    verification_tones = {"PASS": "pass", "FAIL": "fail", "INCONCLUSIVE": "warn", "INVALID": "invalid"}
    lifecycle_tones = {
        "queued": "muted", "running": "info", "completed": "pass", "cancelled": "warn",
        "failed": "fail", "stale": "invalid", "superseded": "muted",
    }
    verification_rows = "".join(
        _state_row(label, states["verification"][label], verification_tones[label])
        for label in ("PASS", "FAIL", "INCONCLUSIVE", "INVALID")
    )
    lifecycle_rows = "".join(
        _state_row(label, states["lifecycle"][label], lifecycle_tones[label])
        for label in ("queued", "running", "completed", "cancelled", "failed", "stale", "superseded")
    )
    exit_rows = "".join(
        "<tr>"
        f'<td><span class="seal-dot" aria-hidden="true"></span>{escape(item["id"])}</td>'
        f'<td><span class="badge badge--pass">{escape(item["status"].upper())}</span></td>'
        f'<td>{len(item["evidence"])}</td>'
        "</tr>"
        for item in snapshot["exits"]
    )
    record_rows = "".join(
        "<li class=" + '"evidence-row">'
        f'<div><span class="eyebrow">{escape(item["kind"])}</span>'
        f'<strong>{escape(item["path"])}</strong></div>'
        f'<code title="{escape(item["sha256"])}">{escape(_short(item["sha256"], 19))}&hellip;</code>'
        "</li>"
        for item in snapshot["source_records"]
    )
    non_claims = "".join(f"<li>{escape(item)}</li>" for item in snapshot["non_claims"])
    attempts = snapshot["retained_attempts"]
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>IncidentSeal Evidence Desk</title>
  <link rel="stylesheet" href="/assets/dashboard.css">
  <script src="/assets/dashboard.js" defer></script>
</head>
<body data-scenario="{escape(scenario["id"])}" data-scenario-kind="{escape(scenario["kind"])}">
  <a class="skip-link" href="#main">Skip to evidence</a>
  <header class="site-header">
    <a class="wordmark" href="#top" aria-label="IncidentSeal evidence desk home">
      <span class="wordmark-mark" aria-hidden="true">IS</span>
      <span>IncidentSeal</span>
    </a>
    <nav aria-label="Evidence sections">
      <a href="#checkpoint">Checkpoint</a><a href="#states">States</a><a href="#provenance">Provenance</a><a href="#limits">Limits</a>
    </nav>
    <span class="mode-pill">Local / read only</span>
  </header>
  <main id="main">
    <section class="hero" id="top" aria-labelledby="hero-title">
      <div class="hero-copy">
        <p class="eyebrow">Evaluation view / {escape(scenario["kind"])}</p>
        <h1 id="hero-title">{escape(hero_title)}</h1>
        <p class="hero-lede">{escape(hero_lede)} A local, source-bound view of the exact records behind IncidentSeal&rsquo;s latest verified checkpoint.</p>
        <div class="identity-strip" aria-label="Checkpoint identity">
          <div><span>Repository</span><strong>drwbkr1 / incidentseal</strong></div>
          <div><span>Commit</span><code>{escape(_short(source["peeled_commit"]))}</code></div>
          <div><span>Tree</span><code>{escape(_short(source["tree"]))}</code></div>
        </div>
      </div>
      <div class="seal seal--{scenario_tone}" aria-label="{escape(scenario["rendered_label"])}">
        <div class="seal-ring"><span class="seal-check" aria-hidden="true">&#10003;</span><strong>{escape(scenario["rendered_label"].upper())}</strong><small>{escape(source["checkpoint"])}</small></div>
        <p>Exit {scenario["exit_code"]} / {escape(scenario["evidence_condition"])}</p>
      </div>
    </section>

    <section class="scenario-bar" aria-label="Evaluation scenario state">
      <div><span>Lifecycle</span><strong>{escape(lifecycle)}</strong></div>
      <div><span>Run verdict</span><strong>{escape(run_verdict)}</strong></div>
      <div><span>Observation</span><strong>{escape(observation_verdict)}</strong></div>
      <div><span>Claim calibration</span><strong>{escape(claim_text)}</strong></div>
    </section>

    <section class="section-grid" id="checkpoint" aria-labelledby="checkpoint-title">
      <div class="section-heading"><p class="eyebrow">01 / checkpoint</p><h2 id="checkpoint-title">Exact identity, visible.</h2><p>The tag, commit, tree, and source records must agree before this view can carry a verified label.</p></div>
      <dl class="identity-card">
        <div><dt>Annotated tag</dt><dd><code>{escape(source["checkpoint"])}</code></dd></div>
        <div><dt>Tag object</dt><dd><code>{escape(source["tag_object"])}</code></dd></div>
        <div><dt>Peeled commit</dt><dd><code>{escape(source["peeled_commit"])}</code></dd></div>
        <div><dt>Tree</dt><dd><code>{escape(source["tree"])}</code></dd></div>
        <div><dt>Snapshot</dt><dd><code>{escape(snapshot["snapshot_digest"])}</code></dd></div>
      </dl>
    </section>

    <section class="section-block" id="states" aria-labelledby="states-title">
      <div class="section-heading section-heading--wide"><p class="eyebrow">02 / state ledger</p><h2 id="states-title">Nothing gets rounded up to PASS.</h2><p>Verification verdicts and execution lifecycle remain independent. Missing and corrupt evidence stay visible.</p></div>
      <div class="ledger-grid">
        <article class="panel"><div class="panel-title"><h3>Verification</h3><span>4 channels</span></div><ul class="state-list">{verification_rows}</ul></article>
        <article class="panel"><div class="panel-title"><h3>Lifecycle</h3><span>7 channels</span></div><ul class="state-list">{lifecycle_rows}</ul></article>
        <article class="panel attention-panel"><div class="panel-title"><h3>Evidence attention</h3><span>kept separate</span></div>
          <div class="attention-value"><strong>{states["missing_evidence"]}</strong><span>missing</span></div>
          <div class="attention-value"><strong>{states["corrupt_evidence"]}</strong><span>corrupt</span></div>
          <p>Neither condition can inherit a successful run verdict.</p></article>
      </div>
    </section>

    <section class="section-grid exits-section" aria-labelledby="exits-title">
      <div class="section-heading"><p class="eyebrow">03 / exit ledger</p><h2 id="exits-title">Every milestone gate accounted for.</h2><p>Eight completed exits point back to allowlisted raw records, not a mutable dashboard database.</p></div>
      <div class="table-wrap"><table><caption class="sr-only">Checkpoint exit conditions</caption><thead><tr><th scope="col">Exit</th><th scope="col">Status</th><th scope="col">Sources</th></tr></thead><tbody>{exit_rows}</tbody></table></div>
    </section>

    <section class="section-block" id="provenance" aria-labelledby="provenance-title">
      <div class="section-heading section-heading--wide"><p class="eyebrow">04 / provenance</p><h2 id="provenance-title">Seven records. Raw bytes bound.</h2><p>Every displayed source is allowlisted and checked against its exact SHA-256 digest before serving.</p></div>
      <ol class="evidence-list">{record_rows}</ol>
    </section>

    <section class="section-grid negative-section" aria-labelledby="negative-title">
      <div class="section-heading"><p class="eyebrow">05 / retained evidence</p><h2 id="negative-title">The failed paths stay in the story.</h2><p>Corrected attempts do not erase earlier invalid, failed, stale, cancelled, or superseded evidence.</p></div>
      <div class="attempt-board">
        <div><strong>{attempts["invalid"]}</strong><span>invalid attempts</span></div>
        <div><strong>{attempts["superseded"]}</strong><span>superseded</span></div>
        <div><strong>{attempts["fail"]}</strong><span>verification fails</span></div>
        <div><strong>{attempts["cancelled"] + attempts["failed"] + attempts["stale"]}</strong><span>lifecycle exceptions</span></div>
      </div>
    </section>

    <section class="limits" id="limits" aria-labelledby="limits-title">
      <div><p class="eyebrow">06 / authority boundary</p><h2 id="limits-title">This view cannot approve, execute, or release.</h2></div>
      <div class="boundary-grid"><div><span>Approval</span><strong>{escape(snapshot["authority"]["approval_status"])}</strong></div><div><span>Bind</span><strong>127.0.0.1</strong></div><div><span>Methods</span><strong>GET / HEAD</strong></div><div><span>Network</span><strong>local only</strong></div></div>
      <ul class="non-claims">{non_claims}</ul>
    </section>
  </main>
  <footer><span>IncidentSeal evidence desk</span><span>Snapshot <code>{escape(_short(snapshot["snapshot_digest"], 19))}&hellip;</code></span></footer>
</body>
</html>
"""
    return html.encode("utf-8")


def build_scenario_application(root: Path, scenario_id: str) -> DashboardApplication:
    """Build one fixed corpus view without exposing scenario selection to HTTP."""

    root_resolved = root.resolve()
    snapshot = strict_load_bytes(_load_fixed(root_resolved, SNAPSHOT_PATH))
    if not isinstance(snapshot, dict):
        raise DashboardSurfaceError("IS_DASHBOARD_SNAPSHOT", "dashboard snapshot is not an object")
    validate_snapshot(snapshot, root_resolved)
    corpus = strict_load_bytes(_load_fixed(root_resolved, CORPUS_PATH))
    if not isinstance(corpus, dict):
        raise DashboardSurfaceError("IS_DASHBOARD_SCENARIO", "dashboard corpus is not an object")
    validate_corpus(corpus)
    scenario = next((item for item in corpus["scenarios"] if item["id"] == scenario_id), None)
    if scenario is None:
        raise DashboardSurfaceError("IS_DASHBOARD_SCENARIO", f"unknown fixed scenario: {scenario_id}")
    snapshot_bytes = canonical_bytes(snapshot)
    css_bytes = _load_fixed(root_resolved, ASSET_ROOT / "dashboard.css")
    javascript_bytes = _load_fixed(root_resolved, ASSET_ROOT / "dashboard.js")
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
        html_bytes=render_dashboard(snapshot, scenario),
        css_bytes=css_bytes,
        javascript_bytes=javascript_bytes,
        health_bytes=health_bytes,
    )


def build_application(root: Path) -> DashboardApplication:
    """Load and freeze the production success view before the socket is opened."""

    return build_scenario_application(root, "dashboard-success")


class DashboardServer(ThreadingHTTPServer):
    """IPv4-only server carrying one immutable application projection."""

    address_family = socket.AF_INET
    daemon_threads = False
    block_on_close = True

    def __init__(self, port: int, application: DashboardApplication) -> None:
        self.application = application
        super().__init__((BIND_HOST, port), DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Fixed-route request handler with no filesystem or authority operations."""

    protocol_version = "HTTP/1.1"
    server_version = "IncidentSeal"
    sys_version = ""

    @property
    def application(self) -> DashboardApplication:
        return self.server.application  # type: ignore[attr-defined,no-any-return]

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: object) -> None:
        return

    def _host_is_valid(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host") == f"{BIND_HOST}:{port}"

    def _send(self, status: int, content_type: str, body: bytes, *, include_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _error(self, status: int, code: str, *, include_body: bool) -> None:
        body = canonical_bytes({
            "schema_version": "incidentseal-dashboard-error/v1",
            "status": status,
            "error": code,
        })
        self._send(status, "application/json; charset=utf-8", body, include_body=include_body)

    def _read(self, *, include_body: bool) -> None:
        if not self._host_is_valid():
            self._error(421, "IS_DASHBOARD_HOST", include_body=include_body)
            return
        target = urlsplit(self.path)
        if target.query or target.path not in ROUTES:
            self._error(404, "IS_DASHBOARD_ROUTE", include_body=include_body)
            return
        routes = {
            "/": ("text/html; charset=utf-8", self.application.html_bytes),
            "/assets/dashboard.css": ("text/css; charset=utf-8", self.application.css_bytes),
            "/assets/dashboard.js": ("text/javascript; charset=utf-8", self.application.javascript_bytes),
            "/api/snapshot": ("application/json; charset=utf-8", self.application.snapshot_bytes),
            "/healthz": ("application/json; charset=utf-8", self.application.health_bytes),
        }
        content_type, body = routes[target.path]
        self._send(200, content_type, body, include_body=include_body)

    def do_GET(self) -> None:
        self._read(include_body=True)

    def do_HEAD(self) -> None:
        self._read(include_body=False)

    def _write_denied(self) -> None:
        self.send_response(405)
        self.send_header("Allow", ", ".join(ALLOWED_METHODS))
        body = canonical_bytes({
            "schema_version": "incidentseal-dashboard-error/v1",
            "status": 405,
            "error": "IS_DASHBOARD_METHOD",
        })
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    do_POST = _write_denied
    do_PUT = _write_denied
    do_PATCH = _write_denied
    do_DELETE = _write_denied
    do_OPTIONS = _write_denied
    do_CONNECT = _write_denied
    do_TRACE = _write_denied


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if port != 0 and not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 0 or between 1024 and 65535")
    return port


def serve(root: Path, port: int, max_requests: int = 0) -> int:
    """Build the immutable projection, bind loopback, and serve until interrupted."""

    application = build_application(root)
    with DashboardServer(port, application) as server:
        actual_port = int(server.server_address[1])
        startup = {
            "schema_version": "incidentseal-dashboard-startup/v1",
            "status": "ready",
            "bind_host": BIND_HOST,
            "port": actual_port,
            "allowed_methods": list(ALLOWED_METHODS),
            "read_only": True,
            "snapshot_digest": application.snapshot["snapshot_digest"],
            "dashboard_creates_authority": False,
            "max_requests": max_requests,
        }
        print(json.dumps(startup, sort_keys=True, separators=(",", ":")), flush=True)
        try:
            if max_requests:
                server.timeout = 10
                for _ in range(max_requests):
                    server.handle_request()
            else:
                server.serve_forever(poll_interval=0.1)
        except KeyboardInterrupt:
            return 0
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="incidentseal-dashboard")
    parser.add_argument("--port", type=_port, default=0)
    parser.add_argument("--max-requests", type=int, choices=range(1, 1001))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    try:
        return serve(root, args.port, args.max_requests or 0)
    except Exception as error:
        code = error.code if isinstance(error, DashboardSurfaceError) else "IS_DASHBOARD_STARTUP"
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-startup/v1",
            "status": "invalid",
            "error": {"code": code, "message": str(error)},
        }, sort_keys=True, separators=(",", ":")), flush=True)
        return 12


if __name__ == "__main__":
    sys.exit(main())
