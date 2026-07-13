# Lab: A First Governed Policy

A runnable OPA lab for the "Getting Started with the EnforceAuth Control Plane" course. Real `opa`, no invented tooling.

`policy.rego` ships as a **starter**: the default-deny and the isolation helpers are written for you, but the four allow rules are a `TODO(learner)` stub. The suite starts **red** (four allow tests fail). Your job is to author the rules until it is green. Solutions are not published. Iterate until opa test is green.

## Files

- `policy.rego` — the starter you complete. Default-deny plus the tenant, org, system, and app isolation helpers are provided; the allow rules are a TODO stub.
- `policy_test.rego` — the graded test suite: four allow cases and four deny cases (one hierarchy level each). Do not edit it.
Solutions are not published. Iterate until opa test is green.

## Input shape

```json
{
  "subject": {
    "role": "member",
    "tenant": "acme",
    "org": "payments",
    "system": "ledger",
    "app": "postings"
  },
  "action": "read",
  "resource": {
    "kind": "report",
    "tenant": "acme",
    "org": "payments",
    "system": "ledger",
    "app": "postings"
  }
}
```

## The exercise

Implement the four allow rules in `policy.rego`, one per hierarchy level. Each is a separate `allow if { ... }` block that ORs into the decision:

- Same-tenant `admin` may take **any** action. (tenant-scoped: use `same_tenant`)
- Same-org `publisher` may `publish`. (org-scoped: use `same_org`)
- Same-system `operator` may `restart`. (system-scoped: use `same_system`)
- Same-app `member` may `read`. (app-scoped: use `same_app`)

The isolation helpers are already written. Do not weaken them: `same_tenant` requires `subject.tenant == resource.tenant`; `same_org` also requires `subject.org == resource.org`; `same_system` also requires `subject.system == resource.system`; `same_app` also requires `subject.app == resource.app`. Each level implies the one above it, so scope narrows as you descend. Everything you do not explicitly allow falls through to the default deny.

## What the tests check

- Four **allow** tests: one governed action per level is permitted for the right role within scope (admin/delete, publisher/publish, operator/restart, member/read).
- Four **deny** tests: the same role is denied across the next boundary out (cross-tenant admin, cross-org publisher, cross-system operator, cross-app member). These catch a false allow that breaks isolation. If a rule you write leaks past its level, a deny test fails.

## Run

From the repository root:

```bash
opa test courses/getting-started-writ-control-plane -v
```

Before you start, this reports `FAIL: 4/8` (the four allow tests). When your rules are correct it reports `PASS: 8/8`. Solutions are not published. Iterate until opa test is green.
