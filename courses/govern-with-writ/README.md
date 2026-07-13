# Lab: A Policy Writ Governs and Promotes

A runnable OPA lab for the "Govern with Writ" course. Real `opa`, no invented tooling. The policy here is the kind of artifact Writ signs into a bundle, promotes dev to staging to prod, and audits. `opa` (or Enterprise OPA) is the PDP that actually evaluates it; Writ is the control plane and is not on the request path.

## Files

- `policy.rego` — a default-deny document-access policy. It ships as a **starter**: the `allow` rules are stubbed out with a `TODO(learner)`, so the suite starts red. You author the rules.
- `policy_test.rego` — the graded test suite: three allow cases and three deny cases. Do not edit it; it defines the target behavior.

## Your exercise

Open `policy.rego` and implement the `allow` rules the `TODO(learner)` block describes so that all six tests pass. The rules to author:

- Admins may perform any action on any document.
- Editors may `read` or `write` a document owned by their own org (`input.subject.org == input.resource.org`).
- Viewers may `read` a document owned by their own org.
- Everything else falls through to the default deny.

Write these as incremental `allow if { ... }` rules that OR together on top of `default allow := false`. Use the `in` operator for the action check (for example, `input.action in {"read", "write"}`).

## Input shape

```json
{
  "subject": { "role": "editor", "org": "acme" },
  "action": "write",
  "resource": { "kind": "document", "org": "acme" }
}
```

## What the tests check

The three allow tests assert the policy returns `allow` for a valid admin, editor, and viewer request. The three deny tests are the ones that catch a false allow: an editor writing across orgs, a viewer writing in their own org, and an unknown role reading. Those deny tests are what a Writ promotion gate would rely on to block a bad bundle.

## Run

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
opa test courses/govern-with-writ -v
```

Starter state: `FAIL: 3/6` (the three allow tests fail until you implement the rules). Target: `PASS: 6/6`. Keep iterating until `opa test` is green.

## How Writ would govern this file

This lab does not run Writ (Writ is a control plane, not a local CLI). It shows the artifact Writ operates on. In a real deployment:

1. This `policy.rego` lives in Git. On merge, Writ auto-builds it into a **signed bundle**.
2. Writ promotes that bundle **dev to staging to prod** with one-click promotion. The same signed bytes move forward; nothing is rebuilt per environment.
3. The PDP (OPA or Enterprise OPA) pulls the bundle and evaluates it on every request. Writ records **decision logs** and supports **replay** so a past decision can be re-run against a candidate policy.

## Going further

Once the suite is green, add a rule so editors may also `delete` a document owned by their own org, then add one allow test for it and one deny test proving an editor still cannot `delete` across orgs. If a change ever lets a viewer write, or lets any role act across orgs, a deny test should fail. That is the point: the deny tests are what a Writ promotion gate would rely on to block a bad bundle.
