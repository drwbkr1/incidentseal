# IncidentSeal status

- Current checkpoint: `IS-0003`
- Latest verified checkpoint: `IS-0002`
- State: active
- Version: `0.0.0`
- Canonical root: `C:\Projects\Active\incidentseal`
- Expected public remote: `https://github.com/drwbkr1/incidentseal.git`
- Expected branch: `main`
- Verified public IS-0002 candidate: `9cafb72f418edd3e3808c30fabda2e56bfee228a` on local, remote `main`, and fresh public clone
- Expected checkpoint marker: `checkpoint-is-0002` (created and verified after the closure record is committed)
- Approved workflow manifest digest: not established
- Application surfaces: not implemented
- Release state: unreleased

## Current truth

The product name, promise, trust boundary, public repository owner, presentation direction, Apache-2.0 license, and long-running operating authority were approved on 2026-08-09. `IS-0002` now establishes the public manifest authority and real host CLI contract: exact local and public clean clones passed both checkout launchers, 38 tests, full Draft 2020-12 schema validation, approval denial, frozen mutations, and 50 fail-closed executions without Docker or real approval state.

The canonical repository is not in OneDrive. All OneDrive paths are forbidden for IncidentSeal work.

## Active unit

`IS3-U01` is the sole eligible unit after the checkpoint marker is live-verified. It may revalidate the initial source gate and acquire the four exact image artifacts into local Docker custody without running them, then retain platform identity, SBOM, provenance, license, and vulnerability evidence. Image execution remains blocked until that disposition passes.

## Known limitations

- The checkout CLI implements policy lint, digest, status, diff, and the TTY-only operator approval command; verification and run events remain unimplemented.
- No Compose topology or database exists.
- No workflow digest is approved and workflow execution remains unavailable.
- Four exact image artifacts passed the source gate only for digest recording and controlled acquisition; none has been pulled, scanned, executed, or approved for runtime use.
- Direct Codex CLI execution currently fails with `Access is denied`.
- The verified `IS-0001` tag and remote `main` both resolve to `55ad47d250041c2148c0f458d276e62d8f02a25d`.

## Next eligible action

Create and independently verify `checkpoint-is-0002` at the closure commit. Then execute `IS3-U01` in `contracts/IS-0003.json`: revalidate the image source gate, acquire exact artifacts without running them, and retain SBOM, provenance, license, scan, and platform-digest evidence before any runtime decision.
