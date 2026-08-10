# Dashboard scenario and evaluation contract

The deterministic corpus contains exactly nine cases in fixed order: success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupt receipt, crash, and recovery. Each case fixes the lifecycle, run verdict, observation verdict, exit code, evidence condition, claim permission, rendered state label, and required visible sections.

Every implementation evaluation must repeat the full corpus, not select a favorable subset. Repeated trials report exact case correctness, false-PASS count, false-release-claim count, projection and render latency distributions, peak process memory, response bytes, local request failures, source-record coverage, and claim calibration. Missing metrics are `INCONCLUSIVE`; malformed metrics are `INVALID`; a false PASS, false release claim, external request, write, non-loopback bind, or state collapse is `FAIL` or `INVALID` according to evidence validity.

The evaluation report must distinguish contract validation, implementation validation, rendered browser QA, repeated scenario results, and clean public reproduction. It retains failed, invalid, interrupted, stale, and superseded attempts rather than replacing them with a later pass.
