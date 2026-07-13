# Lab: A Parity Suite for a Migration

A runnable OPA lab for the "Migrating to EnforceAuth" course. Real `opa`, no invented tooling.

The premise: you are moving an existing authorization policy off a source system (Styra DAS or OPA on OpenShift) onto EnforceAuth without rewriting it. The Rego is unchanged. What you must prove is that the migrated policy decides every request exactly as the old one did. That proof is a parity suite.

This lab ships **RED**. `policy.rego` is a starter: tenant isolation (`same_tenant`) is provided, but the four `allow` decision rules are left as a `# TODO(learner)` stub, so the four allow parity tests fail. You reconstruct the preserved rules until the whole parity suite is green. That mirrors the real work: proving the migrated policy decides exactly as the source system did.

## Files

- `policy.rego` — the policy being migrated. Ships as a starter: `default allow := false` and the `same_tenant` gate are provided; the four allow rules are a `# TODO(learner)` stub for you to complete.
- `policy_test.rego` — the parity suite: four allow cases and four deny cases, each a "golden" decision captured from the source system before the move. Do not edit it; it is the fixed target your policy must satisfy.

## Input shape

```json
{
  "subject": { "id": "u-mem", "role": "member", "tenant": "acme" },
  "action": "delete",
  "resource": {
    "owner": "u-mem",
    "tenant": "acme",
    "classification": "internal"
  }
}
```

## Rules (preserved from the source system)

- Tenant isolation: a subject can only act within its own tenant.
- Admins have full access within their tenant.
- Editors may read and write within their tenant.
- Anyone in the tenant may read a `public` resource.
- Owners may delete a resource they own.
- Everything else falls through to the default deny.

## Run

```bash
opa test courses/migrating-to-enforceauth -v
```

The starter reports `PASS: 4/8`: the four deny cases already pass under default-deny, and the four allow cases fail until you write the rules. The goal is `PASS: 8/8`.

## Exercise

Open `policy.rego` and replace the `# TODO(learner)` stub with the four preserved allow paths, each as its own `allow if { ... }` rule (rules with the same name are OR-ed together). Every rule must include `same_tenant` so tenant isolation still holds:

1. **Admin** — full access within their own tenant.
2. **Editor** — may `read` and `write` within their tenant, but not `delete`. Use the `in` operator for the action set.
3. **Public read** — anyone in the tenant may `read` a resource classified `public`.
4. **Owner delete** — a subject may `delete` a resource whose `owner` is their own id.

Re-run the suite until you reach `PASS: 8/8`. What each test checks:

- The four allow tests assert the source system's allowed decisions are preserved (admin delete, editor write, member reads public, owner deletes own).
- The four deny tests are the regression guards: cross-tenant admin is denied, editor cannot delete, member cannot read `confidential`, and a non-owner cannot delete. If your rules widen access too far, one of these flips to allow and fails.

Solutions are not published. Iterate until opa test is green.
