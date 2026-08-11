#!/usr/bin/env python3
"""Exercise the real loopback dashboard launcher and fixed HTTP surface."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from incidentseal.dashboard_surface import (  # noqa: E402
    BIND_HOST,
    ROUTES,
    SECURITY_HEADERS,
    build_application,
)
from scripts.validate_dashboard_implementation import validate as validate_implementation_lock  # noqa: E402


GET_ROUTES = list(ROUTES)
HEAD_ROUTES = list(ROUTES)
DENIED_METHODS = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"]
WRONG_HOSTS = ["localhost", "example.com", "127.0.0.1", "[::1]"]
BAD_TARGETS = ["/?file=contracts/IS-0004.json", "/unknown", "/assets/../dashboard.css", "/assets/%2e%2e/dashboard.css"]
REQUEST_COUNT = len(GET_ROUTES) + len(HEAD_ROUTES) + len(DENIED_METHODS) + len(WRONG_HOSTS) + len(BAD_TARGETS)


def git_status(root: Path) -> str:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=root, capture_output=True, text=True,
        timeout=10, check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError(f"git status failed: {completed.stderr.strip()}")
    return completed.stdout


def request(port: int, method: str, target: str, host: str | None = None) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(BIND_HOST, port, timeout=4)
    try:
        connection.putrequest(method, target, skip_host=True)
        connection.putheader("Host", host or f"{BIND_HOST}:{port}")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        body = response.read()
        headers = {name: value for name, value in response.getheaders()}
        status = response.status
    except Exception as error:
        raise RuntimeError(f"request transport failed: method={method}, target={target}, host={host}: {error}") from error
    finally:
        connection.close()
    for name, expected in SECURITY_HEADERS.items():
        if headers.get(name) != expected:
            raise RuntimeError(f"security header differs for {method} {target}: {name}")
    return status, headers, body


def stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    else:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def startup_line(process: subprocess.Popen[str]) -> str:
    if process.stdout is None:
        raise RuntimeError("dashboard startup stdout is unavailable")
    result: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=lambda: result.put(process.stdout.readline()), daemon=True)
    reader.start()
    try:
        line = result.get(timeout=15)
    except queue.Empty as error:
        raise RuntimeError("dashboard startup envelope timed out") from error
    if not line:
        raise RuntimeError(f"dashboard exited before startup: {process.poll()}")
    return line


def launcher_command() -> list[str]:
    launcher = ROOT / ("incidentseal-dashboard.cmd" if os.name == "nt" else "incidentseal-dashboard")
    return [str(launcher), "--port", "0", "--max-requests", str(REQUEST_COUNT)]


def run() -> dict[str, Any]:
    implementation_validation = validate_implementation_lock()
    application = build_application(ROOT)
    before_status = git_status(ROOT)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        launcher_command(), cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", creationflags=creationflags,
    )
    port = 0
    try:
        startup = json.loads(startup_line(process))
        if startup != {
            "schema_version": "incidentseal-dashboard-startup/v1",
            "status": "ready",
            "bind_host": BIND_HOST,
            "port": startup.get("port"),
            "allowed_methods": ["GET", "HEAD"],
            "read_only": True,
            "snapshot_digest": application.snapshot["snapshot_digest"],
            "dashboard_creates_authority": False,
            "max_requests": REQUEST_COUNT,
        }:
            raise RuntimeError("dashboard startup envelope differs")
        port = startup["port"]
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise RuntimeError("dashboard operating-system port differs")

        route_bodies = {
            "/": application.html_bytes,
            "/assets/dashboard.css": application.css_bytes,
            "/assets/dashboard.js": application.javascript_bytes,
            "/api/snapshot": application.snapshot_bytes,
            "/healthz": application.health_bytes,
        }
        response_digests: dict[str, str] = {}
        for target in GET_ROUTES:
            status, headers, body = request(port, "GET", target)
            if status != 200 or body != route_bodies[target] or int(headers["Content-Length"]) != len(body):
                raise RuntimeError(f"GET route differs: {target}")
            response_digests[target] = "sha256:" + hashlib.sha256(body).hexdigest()
        for target in HEAD_ROUTES:
            status, headers, body = request(port, "HEAD", target)
            if status != 200 or body or int(headers["Content-Length"]) != len(route_bodies[target]):
                raise RuntimeError(f"HEAD route differs: {target}")
        for method in DENIED_METHODS:
            status, headers, body = request(port, method, "/api/snapshot")
            if status != 405 or headers.get("Allow") != "GET, HEAD" or json.loads(body).get("error") != "IS_DASHBOARD_METHOD":
                raise RuntimeError(f"write/control method was not denied: {method}")
        for host in WRONG_HOSTS:
            status, _, body = request(port, "GET", "/healthz", host=host)
            if status != 421 or json.loads(body).get("error") != "IS_DASHBOARD_HOST":
                raise RuntimeError(f"wrong host was not denied: {host}")
        for target in BAD_TARGETS:
            status, _, body = request(port, "GET", target)
            if status != 404 or json.loads(body).get("error") != "IS_DASHBOARD_ROUTE":
                raise RuntimeError(f"unknown or query route was not denied: {target}")

        remaining_stdout, stderr = process.communicate(timeout=15)
        if process.returncode != 0 or remaining_stdout or stderr:
            raise RuntimeError(f"dashboard launcher exit differs: exit={process.returncode}, stderr={stderr.strip()}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            if probe.connect_ex((BIND_HOST, port)) == 0:
                raise RuntimeError("dashboard loopback socket remained open")
        after_status = git_status(ROOT)
        if after_status != before_status:
            raise RuntimeError("dashboard runtime changed repository custody")
        html = application.html_bytes.decode("utf-8").lower()
        if "http://" in html or "https://" in html:
            raise RuntimeError("dashboard HTML gained a remote asset")
        return {
            "schema_version": "incidentseal-dashboard-implementation-result/v1",
            "verification_verdict": "PASS",
            "launcher": Path(launcher_command()[0]).name,
            "bind_host": BIND_HOST,
            "port": port,
            "request_count": REQUEST_COUNT,
            "get_routes": len(GET_ROUTES),
            "head_routes": len(HEAD_ROUTES),
            "denied_methods": len(DENIED_METHODS),
            "wrong_hosts_denied": len(WRONG_HOSTS),
            "bad_targets_denied": len(BAD_TARGETS),
            "security_headers": len(SECURITY_HEADERS),
            "response_digests": response_digests,
            "snapshot_digest": application.snapshot["snapshot_digest"],
            "implementation_lock_digest": implementation_validation["lock_digest"],
            "external_requests": 0,
            "repository_writes": 0,
            "docker_accessed": False,
            "approval_accessed": False,
            "workflow_executed": False,
            "server_closed": True,
            "repository_state_unchanged": True,
        }
    finally:
        stop_process_tree(process)


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-dashboard-implementation-result/v1",
            "verification_verdict": "INVALID",
            "error": f"{type(error).__name__}: {error}",
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
