# Backup and clean-restore contract mutations

The bounded dependency-free matrix requires eighteen unsafe or contradictory receipts to fail closed:

1. unknown receipt fields;
2. smuggled approved-workflow authority;
3. a non-disposable source;
4. PostgreSQL version drift;
5. plain-SQL archive substitution;
6. concurrent source writes;
7. restored ownership or privileges in the dump command;
8. disabled fsync;
9. roles restored from dump SQL;
10. a superuser application runner;
11. archive substitution at restore;
12. source-project reuse;
13. removal of restore error stopping;
14. restored schema drift;
15. runner journal access;
16. changed protected-volume identity;
17. retained disposable restore custody; and
18. a tampered receipt digest.

Each semantic mutation refreshes its receipt digest so the intended contract gate, rather than a stale identity, rejects it. The identity mutation alone retains the tampered digest. No mutation starts Docker or PostgreSQL.
