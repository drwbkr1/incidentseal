# Read-only dashboard implementation

The dashboard is a separate dependency-free host process. It does not add a command to the frozen `incidentseal` verification CLI and has no Docker, Compose, approval, workflow, secret, repository-write, analytics, telemetry, or external-network capability.

On Windows, start the current locked surface with an operating-system-assigned port:

```powershell
.\incidentseal-dashboard.cmd --port 0
```

The first stdout line is a machine-readable startup envelope containing the exact IPv4 loopback endpoint and snapshot digest. Open only the reported `http://127.0.0.1:PORT/` URL. Stop the process with Ctrl+C. On POSIX systems use `./incidentseal-dashboard --port 0`.

The server accepts only an exact `Host: 127.0.0.1:PORT` header and fixed `GET` or `HEAD` routes: `/`, `/assets/dashboard.css`, `/assets/dashboard.js`, `/api/snapshot`, and `/healthz`. Queries, arbitrary paths, traversal, write methods, control methods, remote assets, and non-loopback hosts fail closed. Responses use no-store caching and eight defensive security headers.

`--max-requests` is a bounded validation lifecycle control used by the real-surface harness; it does not add a route, input source, filesystem path, or authority surface. The default remains long-running. The nine frozen adversarial views are built only through the internal fixed corpus evaluator and cannot be selected through HTTP or launcher input.

Run the exact locked implementation check with:

```powershell
python -B scripts\validate_dashboard_implementation.py
python -B scripts\run_dashboard_implementation.py
```

These checks do not prove rendered browser quality or accessibility. That remains a separate real-browser gate.
