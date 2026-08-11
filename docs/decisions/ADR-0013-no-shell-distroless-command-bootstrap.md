# ADR-0013: Clear effective command environment inside the pinned language runtime

- Status: accepted for IS6-U02 candidate evaluation
- Date: 2026-08-11

## Context

The exact source-gated distroless Python and Node images contain immutable image-level `PATH` and certificate configuration but intentionally contain no shell or `env` utility. The workflow contract forbids host-environment forwarding and gives the user command only four approved environment variables. Rebuilding or silently changing the pinned image identity would break the source and runtime locks; treating inherited image metadata as forwarded host state would blur the evidence boundary.

## Decision

IncidentSeal starts the exact language entrypoint with direct argv and a small language-native bootstrap. The bootstrap removes its private encoded argument and clears the effective user-command environment before invoking user code. Python v1 admits direct scripts, `-m`, and `-c` profiles in-process; Node uses `spawnSync` with `shell:false`. The effective command sees only `HOME`, `PYTHONDONTWRITEBYTECODE`, `PYTHONHASHSEED`, and `TZ`.

The container still must pass exact image, label, user, mount, network, root-filesystem, capability, no-new-privileges, process, memory, and tmpfs inspection before start. No shell, host command, secret, socket, host environment, or alternate image is introduced.

## Consequences

The v1 Python argument profile is intentionally narrower than the general interpreter CLI. Unsupported interpreter flag profiles are `INVALID` before Docker. A future broader profile requires a new reviewed contract; it cannot be inferred from arbitrary manifest argv.
