# Receipt contract mutation plan

The dependency-free contract validator must accept the golden portable bundle, reproduce every event, link, root, receipt, and artifact digest, and reject each bounded mutation with its expected stable `IS_RECEIPT_*` code.

The required mutations cover unknown fields, authority-mode smuggling, authority drift, duplicate bindings, event reordering and truncation, event and predecessor corruption, root corruption, run-state collapse, terminal-event drift, artifact digest corruption, unsafe paths, and a false `PASS` without an expected receipt digest.

Mutation cases operate only on temporary in-memory or system-temporary copies of fixed non-sensitive fixtures. They do not invoke Docker, read approval state, write runtime evidence, or touch retained volumes.
