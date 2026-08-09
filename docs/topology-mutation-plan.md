# Topology fail-closed mutation plan

The dependency-free topology validator must accept the frozen contract and normalized render fixture, then reject every bounded mutation below even when the corresponding lock digest is recomputed. Recomputing the digest during the test proves that semantic gates—not stale hashes alone—protect the boundary.

| Mutation | Required result |
| --- | --- |
| Move Docker control from `host-cli` to a container | `FAIL` |
| Remove the workflow `MATCH` requirement | `FAIL` |
| Allow repository input during platform validation | `FAIL` |
| Make the `data` network non-internal or external | `FAIL` |
| Publish any service port | `FAIL` |
| Add a Docker socket or engine endpoint mount | `FAIL` |
| Run the database or a runner as root | `FAIL` |
| Enable privileged mode or retain a capability | `FAIL` |
| Make a root filesystem writable | `FAIL` |
| Replace an exact locked image with a tag | `FAIL` |
| Add build networking, `RUN`, a secret, SSH, or online resolution | `FAIL` |
| Mount the repository instead of staged custody | `FAIL` |
| Collapse a verdict or lifecycle state | `FAIL` |
| Treat config render or source tests as runtime proof | `FAIL` |

The mutation harness reads machine fixtures from `fixtures/topology/mutations.json`. It operates only in temporary copies, retains machine-readable results, and never calls Docker.
