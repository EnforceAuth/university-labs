# Lab: The Bundle That Travels the Pipeline

A runnable OPA lab for the "Policy Lifecycle: Build, Promote & Roll Back" course. Real `opa`, no invented tooling.

`policy.rego` ships as a **starter**: it declares `default allow := false` and a `TODO(learner)` block. Your job is to implement the authorization rules until the test suite passes. Solutions are not published. Iterate until opa test is green.

## Files

- `policy.rego` — the OPA bundle being deployed, shipped as a starter for you to complete. It must authorize who may promote or roll back a policy bundle in each environment.
- `policy_test.rego` — the graded test suite: three allow cases and four deny cases. Do not edit it; make it pass.

## Input shape

```json
{
  "subject": { "role": "release-manager" },
  "action": "promote",
  "target": { "environment": "prod", "bundle": "authz-core" },
  "change": { "approved": true, "commit_sha": "a1b2c3d" }
}
```

## The exercise

Open `policy.rego` and replace the `TODO(learner)` block with incremental `allow if { ... }` rules that implement every line of the policy below. In Rego, multiple `allow if` rules OR together, and any request that matches none is denied by `default allow := false`.

- Admins may promote or roll back in any environment.
- Engineers and release managers may promote to `dev` with a pinned `commit_sha` (an arbitrary role such as `intern` is denied even with a commit).
- Release managers may promote to `staging` with a pinned `commit_sha`.
- Promotion to `prod` requires a release manager and an approved change.
- Rollback in `prod` restores a prior bundle by `commit_sha` (release managers).
- Everything else falls through to the default deny.

## What the tests check

`policy_test.rego` uses `with input as { ... }` to drive the policy for each case:

- **Allow cases** — an engineer promoting to `dev` with a commit, a release manager promoting to `prod` when the change is approved, a release manager rolling back `prod` by a prior `commit_sha`. Until you implement the rules, these three fail.
- **Deny cases** — an engineer promoting to `prod`, a release manager promoting to `prod` unapproved, a `dev` promotion with no commit, and a non-deployer role (`intern`) promoting to `dev`. These catch a policy that over-grants. A default-deny stub passes them for free; keep them passing as you add rules.

## Run

```bash
opa test courses/policy-lifecycle-build-promote-rollback -v
```

Run it from the repository root. The starter reports `FAIL: 3/7` (the three allow cases). When your implementation is complete you should see `PASS: 7/7`. Solutions are not published. Iterate until opa test is green.

## Build the deployable artifact

`opa test` gates the bundle; `opa build` produces it. Compile this directory into a single bundle tarball, stamping a `commit_sha` as the manifest revision and leaving the test file out of the shipped artifact:

```bash
opa build -b courses/policy-lifecycle-build-promote-rollback \
  -r 9f8e7d6 --ignore '*_test.rego' -o bundle.tar.gz
opa inspect bundle.tar.gz
```

Run it from the repository root. The starter compiles, so the build succeeds before you finish the exercise; `opa test`, not `opa build`, is what decides whether the artifact may promote. `bundle.tar.gz` is the artifact Writ signs and `deploy-action` ships (lesson 2).

## Why this policy is the lab

This is the artifact the pipeline moves. In the lessons, `deploy-action` deploys this same bundle over GitHub OIDC (no API keys), Writ signs and promotes it dev to staging to prod, and a rollback restores a prior `commit_sha`. The Rego here is what the PDP (OPA or Enterprise OPA) actually evaluates at each stage. Testing it before promotion is the gate that keeps a broken bundle out of prod, which is exactly why the deny tests matter: they fail loudly if your policy would over-grant in production.
