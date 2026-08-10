# Dashboard visual acceptance matrix

## Required views

1. Desktop at `1440x900`: checkpoint seal and identity, milestone exits, state ledger, evidence provenance, retained negative evidence, and non-claims are visible in one coherent evidence-desk layout.
2. Mobile at `390x844`: the same information remains ordered, readable, and reachable without horizontal overflow or hidden state.
3. Missing, corrupt, and invalid evidence: the problem, affected source identity, verification consequence, and next safe action are explicit.
4. No-data and loading-independent startup: the server-rendered shell never implies PASS before the exact snapshot is present.

## Accessibility and interaction

- One `main` landmark, labelled navigation, ordered headings, real tables or lists for repeated data, and textual state labels.
- Complete keyboard traversal with a visible focus indicator and no keyboard trap.
- Text contrast at least `4.5:1`; large text and non-text state indicators at least `3:1`.
- State is never communicated only by color, icon, position, or motion.
- `prefers-reduced-motion` removes nonessential animation without hiding content.
- Touch targets are at least 44 CSS pixels where controls exist.

## Evidence required later

Rendered desktop and mobile screenshots, DOM/landmark inspection, keyboard receipts, responsive overflow measurements, security headers, loopback binding, route/method denial, local-asset proof, and snapshots for every frozen scenario. Source inspection and unit tests alone cannot pass this matrix.
