# Environment inventory

- Inventory ID: `IS-ENV-20260809-01`
- Observed at: `2026-08-09T05:13:18Z`
- Canonical root: `C:\Projects\Active\incidentseal`
- Forbidden custody root: `C:\Users\drewb\OneDrive`
- Method: local read-only CLI and Windows package inspection

## Repository

- Git `2.52.0.windows.1`
- Branch `main`
- No commits at observation time
- No remote at observation time
- Expected public remote: `https://github.com/drwbkr1/incidentseal.git`

## Docker runtime

- Docker Desktop `4.74.0.227015`
- Docker client/server `29.4.3`
- Engine API `1.54`
- Docker Compose `5.1.3`
- Docker Buildx `0.33.0-desktop.1`
- BuildKit `0.29.0`
- Active context `desktop-linux`
- Engine OS/architecture `linux/amd64`
- Kernel `6.6.114.1-microsoft-standard-WSL2`
- Storage driver `overlayfs`
- Cgroup v2
- Security options reported: builtin seccomp and cgroup namespaces
- Available to Docker: 12 CPUs and 16,591,708,160 bytes of memory
- Docker Scout `1.20.4`, commit `27a30b2a666b98e09711750a62eb70f15c779737`

## Language tooling

- Python `3.12.10`
- pip `25.0.1`
- uv `0.10.7`
- Node.js `24.15.0`
- npm `11.12.1`
- Corepack `0.34.6`
- pnpm `11.16.0`

## Absent optional host tools

- `psql`
- `pg_isready`
- `cosign`
- `syft`
- `grype`
- `trivy`

PostgreSQL and its client tools should therefore be exercised through source-gated containers. Docker Scout is the only currently installed host scanner candidate; absence or failure of scan evidence remains `INCONCLUSIVE`.

## Codex

- Windows package `OpenAI.Codex` version `26.730.8199.0`, package status `Ok`
- Direct `codex --version` invocation from PowerShell failed with `Access is denied`

The Codex machine-readable integration is not verified. A later checkpoint must resolve and test the actual noninteractive executable surface before making integration claims.

## Inventory limitations

- This is a point-in-time local inventory, not a portability claim.
- No candidate image was pulled or executed during this inventory.
- Registry access, GitHub access, image provenance, signatures, licenses, and vulnerabilities require separate live gates.
