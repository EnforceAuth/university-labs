# Lab: Hello, Authorization

A minimal, runnable OPA lab for the reference course. Real `opa`, no invented tooling.

## Files

- `policy.rego` — a default-deny authorization policy. It ships as a **starter**: the `allow` rule is left as a `TODO(learner)` stub.
- `policy_test.rego` — the graded test suite: three allow cases and three deny cases. Do not edit it.

## Your task

Open `policy.rego`. The `permissions` map (role to permitted actions) is provided, and `default allow := false` is already in place. Implement the missing `allow` rule so that a request is allowed **only when** `input.action` is one of the actions permitted for `input.subject.role` in `permissions`.

Hint: use the `in` operator to test membership in `permissions[<role>]`. An unknown role should leave the lookup undefined so `allow` stays `false`.

## What the tests check

- Allow cases: an admin can `delete`, an editor can `write`, a viewer can `read`. These **fail** in the starter and pass once you implement `allow`.
- Deny cases: a viewer cannot `write`, an editor cannot `delete`, an unknown role (`guest`) is denied. These pass under default-deny and must keep passing. They catch a "false allow," a request granted when policy says it should not be.

## Run

```bash
opa test courses/reference-hello-authorization -v
```

The starter reports `FAIL: 3/6`. Implement the `TODO(learner)` rule until you reach `PASS: 6/6`.

## Reference solution

Solutions are not published. Iterate until opa test is green.

```bash
opa test courses/reference-hello-authorization-solution -v
```
