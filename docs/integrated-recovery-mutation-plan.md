# Integrated receipt and recovery contract mutations

The dependency-free contract evaluator requires twenty-eight authority, state, repeatability, and custody mutations to fail closed:

1. unknown matrix fields;
2. smuggled approved-workflow authority;
3. enabled workflow execution;
4. a container Docker socket;
5. a container secret;
6. external runtime network access;
7. a mounted protected volume;
8. repository temporary custody;
9. only one matrix repetition;
10. a missing stage;
11. reordered stages;
12. arbitrary stage arguments;
13. unbound receipt identity promoted to PASS;
14. corrupt receipt evidence promoted to PASS;
15. invalid receipt identity collapsed into FAIL;
16. completed product FAIL collapsed into lifecycle failed;
17. a cancelled run gaining a verdict;
18. a failed run gaining a verdict;
19. a stale run gaining a verdict;
20. removed superseded evidence;
21. ambiguous recovery promoted to PASS;
22. conflicting recovery promoted to PASS;
23. forced equality of raw archive bytes across fresh dumps;
24. unstable normalized TOC accepted;
25. unstable restored state accepted;
26. changed protected-volume identity accepted;
27. disabled inter-stage teardown; and
28. a tampered matrix digest.

Every semantic mutation refreshes the RFC 8785 matrix digest so the intended contract gate, not a stale identity, rejects it. The digest mutation alone retains its tampered identity. The mutation evaluator has no third-party dependency and starts no runtime.
