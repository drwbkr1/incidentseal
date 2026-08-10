# Event journal contract mutations

The dependency-free contract evaluator must reject semantic drift even when record digests are recomputed. The bounded matrix covers:

1. unknown record fields;
2. idempotency-key drift;
3. event-digest drift;
4. predecessor and link drift;
5. a non-zero first sequence and later sequence gaps;
6. competing bytes at one run sequence;
7. event-ID reuse across runs;
8. different bytes under an existing idempotency key;
9. lifecycle regression;
10. append after a terminal event;
11. a completed event without a verdict;
12. a non-completed event with a verdict;
13. stale evidence without distinct authority digests;
14. supersession that names the same run; and
15. changed authority inside one run.

The baseline must also prove exact replay returns `replayed` without increasing event count or changing root identity.
