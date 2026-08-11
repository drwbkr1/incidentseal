from __future__ import annotations

import http.client
import json
from pathlib import Path
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.dashboard_surface import (  # noqa: E402
    BIND_HOST,
    ROUTES,
    SECURITY_HEADERS,
    DashboardServer,
    _port,
    build_application,
    build_scenario_application,
)


class DashboardSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = build_application(ROOT)
        cls.server = DashboardServer(0, cls.application)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method: str, path: str, *, host: str | None = None) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(BIND_HOST, self.port, timeout=3)
        connection.putrequest(method, path, skip_host=True)
        connection.putheader("Host", host or f"{BIND_HOST}:{self.port}")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        body = response.read()
        headers = {key: value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, headers, body

    def test_projection_binds_exact_checkpoint(self) -> None:
        snapshot = self.application.snapshot
        self.assertEqual(snapshot["source"]["checkpoint"], "checkpoint-is-0004")
        self.assertEqual(snapshot["source"]["peeled_commit"], "25328dacef4d9283090bed809db75b33f613829b")
        self.assertEqual(len(snapshot["source_records"]), 7)

    def test_every_frozen_scenario_has_a_distinct_calibrated_view(self) -> None:
        identifiers = (
            "dashboard-success", "dashboard-product-failure", "dashboard-invalid-input",
            "dashboard-missing-evidence", "dashboard-policy-attack", "dashboard-isolation-attack",
            "dashboard-corrupt-receipt", "dashboard-crash", "dashboard-recovery",
        )
        digests = set()
        for scenario_id in identifiers:
            with self.subTest(scenario_id=scenario_id):
                application = build_scenario_application(ROOT, scenario_id)
                html = application.html_bytes.decode("utf-8")
                self.assertIn(f'data-scenario="{scenario_id}"', html)
                self.assertIn(application.scenario["rendered_label"].upper(), html)
                expected_claim = "Claim permitted" if scenario_id == "dashboard-success" else "Claim withheld"
                self.assertIn(expected_claim, html)
                digests.add(__import__("hashlib").sha256(application.html_bytes).hexdigest())
        self.assertEqual(len(digests), 9)

    def test_unknown_scenario_fails_closed(self) -> None:
        with self.assertRaises(Exception):
            build_scenario_application(ROOT, "dashboard-unknown")

    def test_server_is_ipv4_loopback_only(self) -> None:
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertEqual(self.server.address_family, 2)

    def test_every_fixed_get_route_is_available(self) -> None:
        for route in ROUTES:
            with self.subTest(route=route):
                status, _, body = self.request("GET", route)
                self.assertEqual(status, 200)
                self.assertTrue(body)

    def test_api_snapshot_is_exact_canonical_bytes(self) -> None:
        status, headers, body = self.request("GET", "/api/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.application.snapshot_bytes)
        self.assertEqual(json.loads(body)["snapshot_digest"], self.application.snapshot["snapshot_digest"])
        self.assertTrue(headers["Content-Type"].startswith("application/json"))

    def test_head_returns_headers_without_body(self) -> None:
        for route in ROUTES:
            with self.subTest(route=route):
                status, headers, body = self.request("HEAD", route)
                self.assertEqual(status, 200)
                self.assertEqual(body, b"")
                self.assertGreater(int(headers["Content-Length"]), 0)

    def test_wrong_host_is_rejected(self) -> None:
        for host in ("localhost", f"localhost:{self.port}", "example.com", "127.0.0.1"):
            with self.subTest(host=host):
                status, _, body = self.request("GET", "/healthz", host=host)
                self.assertEqual(status, 421)
                self.assertEqual(json.loads(body)["error"], "IS_DASHBOARD_HOST")

    def test_write_and_control_methods_are_rejected(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"):
            with self.subTest(method=method):
                status, headers, body = self.request(method, "/api/snapshot")
                self.assertEqual(status, 405)
                self.assertEqual(headers["Allow"], "GET, HEAD")
                self.assertEqual(json.loads(body)["error"], "IS_DASHBOARD_METHOD")

    def test_queries_unknown_routes_and_traversal_are_rejected(self) -> None:
        for target in ("/?file=contracts/IS-0004.json", "/unknown", "/assets/../dashboard.css", "/assets/%2e%2e/dashboard.css"):
            with self.subTest(target=target):
                status, _, body = self.request("GET", target)
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(body)["error"], "IS_DASHBOARD_ROUTE")

    def test_every_response_has_defensive_headers(self) -> None:
        for target in ("/", "/api/snapshot", "/unknown"):
            with self.subTest(target=target):
                _, headers, _ = self.request("GET", target)
                for name, expected in SECURITY_HEADERS.items():
                    self.assertEqual(headers[name], expected)

    def test_html_has_required_semantic_landmarks_and_states(self) -> None:
        html = self.application.html_bytes.decode("utf-8")
        self.assertEqual(html.count("<main"), 1)
        self.assertIn("<nav aria-label=", html)
        self.assertIn("<h1", html)
        self.assertIn("<table>", html)
        for label in ("PASS", "FAIL", "INCONCLUSIVE", "INVALID", "cancelled", "failed", "stale", "superseded"):
            self.assertIn(label, html)

    def test_assets_have_no_remote_or_active_network_reference(self) -> None:
        html = self.application.html_bytes.decode("utf-8").lower()
        css = self.application.css_bytes.decode("utf-8").lower()
        javascript = self.application.javascript_bytes.decode("utf-8").lower()
        for content in (html, css, javascript):
            self.assertNotIn("http://", content)
            self.assertNotIn("https://", content)
        for token in ("fetch(", "xmlhttprequest", "websocket", "eventsource"):
            self.assertNotIn(token, javascript)

    def test_port_contract_is_bounded(self) -> None:
        self.assertEqual(_port("0"), 0)
        self.assertEqual(_port("1024"), 1024)
        self.assertEqual(_port("65535"), 65535)
        for invalid in ("-1", "1", "1023", "65536", "text"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(Exception):
                    _port(invalid)


if __name__ == "__main__":
    unittest.main()
