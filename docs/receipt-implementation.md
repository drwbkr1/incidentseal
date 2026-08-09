# Portable receipt implementation

`IS4-U02` adds two dependency-free host CLI surfaces under the frozen `INCIDENTSEAL-RECEIPT-001` contract.

`receipt materialize` strictly parses and semantically validates the source receipt, recomputes event and link hashes, verifies exact artifact bytes, writes canonical receipt and artifact bytes into a same-filesystem staging directory, flushes each file, and atomically renames the directory to `OUTPUT/sha256/DIGEST`. Repeating the command verifies and reuses the exact bundle. A conflicting existing bundle fails closed. Repository and OneDrive output, symlink/reparse custody, path escape, and corrupted source bytes are rejected.

`receipt verify` performs the same schema-independent semantic, chain, state, authority, custody, and artifact checks without writing. With the exact expected digest and exact artifacts it returns `PASS`/0. Without an expected digest it returns `INCONCLUSIVE`/11. Receipt identity mismatch is `INVALID`/12; present corrupt artifact bytes are `FAIL`/10; required missing bytes are `INCONCLUSIVE`/11; malformed or unsafe custody is `INVALID`/12.

Both commands return one `incidentseal-cli-envelope/v1` JSON document. They use no third-party runtime dependency, Docker, Compose, PostgreSQL, network, secret, or approval state. These surfaces implement portable bundle integrity only; they do not yet persist run events or provide crash recovery.
