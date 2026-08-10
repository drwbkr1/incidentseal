# Interruption recovery contract mutations

The dependency-free evaluator must reject semantic drift even when the attacker supplies schema-valid replacement values. The bounded matrix covers:

1. an unknown observation field;
2. journal count/sequence drift;
3. a fabricated verdict on a nonterminal run;
4. a false `MATCH` authority digest;
5. effects at a before-dispatch boundary;
6. an exit code without an exited runtime;
7. retained identity fields on a missing lease;
8. a cancel request disguised as another interruption;
9. resuming while another lease is active;
10. stopping an unowned runtime;
11. promoting ambiguous effects to `PASS`;
12. replaying a non-idempotent step;
13. adding a run verdict to cancellation or process failure;
14. mismatched terminal event and lifecycle;
15. observation-identity drift;
16. decision-identity drift;
17. promoting conflicting effects to recovery `PASS`; and
18. appending evidence without safe lease, ownership, or authority.

The baseline requires all twelve frozen decisions, unique observation and decision digests, exact decision replay, no Docker runtime, and a null run verdict in every case.
