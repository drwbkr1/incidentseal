# Dashboard projection and serving contract

- Contract ID: `INCIDENTSEAL-DASHBOARD-001`
- Unit: `IS5-U01`
- Runtime status: not started

## Claim

The dashboard may display a checkpoint as verified only when a closed snapshot binds the exact repository, checkpoint tag object, peeled commit, tree, source records, exit conditions, evidence counts, retained attempts, trust boundary, and non-claims. The snapshot is a projection, never approval or verification authority.

## Fixed data boundary

The projection reads only an allowlisted set of repository-controlled JSON and JSONL records. Every source path is safe, relative, unique, and accompanied by the exact SHA-256 digest of its raw bytes. It does not query a live database, Docker, an approval store, GitHub, a registry, or the network. Unknown fields, duplicate keys, unsafe paths, missing records, hash drift, ambiguous state, and an unverified checkpoint are `INVALID`.

Verification verdicts are exactly `PASS`, `FAIL`, `INCONCLUSIVE`, and `INVALID`. Lifecycle values are independently counted as `queued`, `running`, `completed`, `cancelled`, `failed`, `stale`, and `superseded`. Missing evidence and corrupt evidence remain separate attention states. A rendered success state cannot replace source identity or make a release claim.

## Fixed serving boundary

The future host launcher is separate from the frozen verification CLI. It binds only IPv4 `127.0.0.1`, accepts a bounded port or operating-system-assigned port, and checks the `Host` header against the active loopback endpoint. It serves only `/`, fixed local assets, `/api/snapshot`, and `/healthz`. Only `GET` and `HEAD` are admitted; write methods, directory listing, path traversal, query-driven file access, uploads, WebSockets, server-sent events, and arbitrary routes are rejected.

Responses use no-store caching and fixed defensive headers, including a local-only Content Security Policy, denied framing, no MIME sniffing, strict referrer policy, and restrictive permissions policy. HTML, CSS, JavaScript, fonts, icons, and images are repository-controlled local assets. There is no analytics, telemetry, external font, CDN, remote image, secret, credential, Docker call, approval access, workflow execution, or repository write.

## Presentation contract

The visual direction is a dark forensic evidence desk, not a generic SaaS card grid. The verified checkpoint seal, exact commit and tag identity, exit-condition ledger, evidence-state distribution, selected record provenance, retained negative evidence, and current non-claims are visible without hiding failure states behind interaction. Color never carries state alone. Desktop and mobile layouts, keyboard order, semantic landmarks, reduced motion, contrast, overflow, empty, missing, corrupt, and invalid states require real rendered evidence.

## Non-claims

This contract starts no server or browser and introduces no runtime dependency. It does not prove the future snapshot builder, HTTP behavior, rendered dashboard, browser accessibility, scenario corpus execution, performance, packaging, registry, downloaded release, or software release.
