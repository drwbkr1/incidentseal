# IncidentSeal status

- Current checkpoint: `IS-0002`
- Latest verified checkpoint: `IS-0001`
- State: active
- Version: `0.0.0`
- Canonical root: `C:\Projects\Active\incidentseal`
- Expected public remote: `https://github.com/drwbkr1/incidentseal.git`
- Expected branch: `main`
- Latest verified checkpoint commit: `55ad47d250041c2148c0f458d276e62d8f02a25d` on local and remote `main`
- Verified checkpoint marker: `checkpoint-is-0001` -> `55ad47d250041c2148c0f458d276e62d8f02a25d`
- Approved workflow manifest digest: not established
- Application surfaces: not implemented
- Release state: unreleased

## Current truth

The product name, promise, trust boundary, public repository owner, presentation direction, Apache-2.0 license, and long-running operating authority were approved on 2026-08-09. `IS-0001` established and live-verified the public non-OneDrive repository, contract, threat model, environment inventory, project controls, and exact-image source boundary without pulling or running a candidate image.

The canonical repository is not in OneDrive. All OneDrive paths are forbidden for IncidentSeal work.

## Active unit

`IS2-U04` completed the repeated fail-closed matrix, and `IS2-U04A` implemented and locally validated the operator-only interactive writer using temporary custody. `IS2-U05` is now the active unit: validate the packaged real CLI and frozen contracts from a clean temporary copy without Docker runtime use.

## Known limitations

- The checkout CLI implements policy lint, digest, status, diff, and the TTY-only operator approval command; verification and run events remain unimplemented.
- No Compose topology or database exists.
- The `IS2-U01` contract artifacts passed their bounded local gate, but the full `IS-0002` checkpoint remains active and no workflow digest is approved.
- Four exact image artifacts passed the source gate only for digest recording and controlled acquisition; none has been pulled, scanned, executed, or approved for runtime use.
- Direct Codex CLI execution currently fails with `Access is denied`.
- The verified `IS-0001` tag and remote `main` both resolve to `55ad47d250041c2148c0f458d276e62d8f02a25d`.

## Next eligible action

Execute `IS2-U05` in `contracts/IS-0002.json`: copy the committed tree into isolated temporary custody and validate real Windows and POSIX launcher behavior, JSON/stdout/stderr/exit discipline, approval boundaries, and dependency-free setup.
