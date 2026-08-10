# Dashboard contract mutation plan

`IS5-U01` rejects bounded changes that broaden authority or custody, alter checkpoint or source identity, collapse evidence states, promote adversarial scenarios, weaken evaluation gates, reduce repeatability, or tamper with either canonical digest. Every mutation is applied to a fresh golden fixture and must return its exact stable error code. Recomputing the digest after a semantic mutation must not make the mutation valid.

The mutation harness starts no server, browser, container, database, workflow, or external request. Runtime and rendered-surface mutations belong to `IS5-U02` and `IS5-U03` after this contract is public-reproduced.
