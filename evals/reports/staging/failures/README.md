# Failure artifacts

Reports here are **failures**, kept because a record that only contains passing
evidence is not a record, it is a highlight reel. Nothing in this directory is
a verdict.

## `readiness-20261118T121638Z.json` — 2 criteria FAIL, commit `21ebf24`

`STAGING_READY` **FAIL** (mode `full`), against a working tree at `21ebf24`.

```
FAIL  oidc token accepted      GET /v1/findings as reviewer-a: HTTP 403
                               {"detail":"principal is not a member of the requested tenant"}
FAIL  expired token rejected   same token: HTTP 403 before expiry, 401 after 100s
```

**Cause (found, fixed).** `make demo-run` provisioned both reviewers for the
fresh rehearsal tenant only. Provisioning *replaces* a subject's tenant list
rather than adding to it, so the run silently de-authorized the reviewers from
the readiness tenant `1111…`. The next readiness probe then failed closed with
403, which is the correct behaviour for a principal that is genuinely not a
member of the tenant it is asking about.

The gate was right and the automation was wrong. `demo-run` now provisions
`$(DEMO_TENANT),$$TENANT`, and prints that it is keeping the readiness tenant
authorized.

**Why it is kept.** It is the artifact that proves the fix was needed. Deleting
it would leave a clean set of passes and no trace of the defect — the same
mistake this work already made once with a refused grounding run.

**One caveat, stated rather than smoothed over.** After the fix, a single
`make demo-up` smoke run failed the `oidc token accepted` check once and then
passed on every subsequent attempt, including a deliberate reproduction of the
exact re-provision / probe sequence. The cause of that one transient was not
identified. The full gate passed immediately afterwards and has passed since.
It is recorded here because a flaky gate is itself a defect, even when it is
not reproducible on demand.
