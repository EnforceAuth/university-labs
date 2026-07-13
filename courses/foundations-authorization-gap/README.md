# Lab: Modeling a PDP Decision

A runnable OPA lab for the "AI Security Fabric & the Authorization Gap" course. Real `opa`, no invented tooling.

This lab ships **RED**: `policy.rego` is a default-deny starter with the decision rules left as a `# TODO(learner)`. Your job is to implement them until the test suite passes.

## Files

- `policy.rego` — a default-deny starter. It denies everything until you add the allow rules.
- `policy_test.rego` — the test suite (unchanged): three allow cases and three deny cases. Do not edit it.

## Input shape

```json
{
  "subject": { "role": "member", "department": "platform" },
  "action": "delete",
  "resource": { "kind": "policy", "owner": "platform" }
}
```

## Your task

Open `policy.rego` and implement the three `allow` rules the `# TODO(learner)` describes. Multiple rules with the same name are a logical OR, so add one `allow if { ... }` block per case:

1. **Admins may delete any resource** — `input.action == "delete"` and `input.subject.role == "admin"`.
2. **Owners may delete a resource their department owns** — `input.action == "delete"` and `input.subject.department == input.resource.owner`.
3. **Members may read** — `input.action == "read"` and `input.subject.role == "member"`.

Everything else must fall through to the `default allow := false`.

## What the tests check

The suite in `policy_test.rego` asserts both directions:

- **Allow cases** — an admin can delete, an owner-department member can delete, a member can read.
- **Deny cases** — a member cannot delete another department's resource, a member cannot write, and an unknown role cannot read. These deny tests are the ones that catch a **false allow**: a rule so broad it grants a request policy should reject.

## Run

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
opa test courses/foundations-authorization-gap -v
```

Before you start you will see `PASS: 3/6` (the three deny tests already pass against default-deny). When your three rules are correct you will see `PASS: 6/6`. Keep iterating until `opa test` is green.
