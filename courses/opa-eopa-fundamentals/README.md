# Lab: OPA & Enterprise OPA Fundamentals

A runnable OPA lab for the Associate course. Standard `opa`, no invented tooling. It also runs unchanged on Enterprise OPA (`eopa`), which is drop-in compatible.

`policy.rego` ships as a **starter**: the scaffolding is written for you and the two decision rules are stubbed with a `# TODO(learner)` block. Your job is to implement them so the test suite passes. Solutions are not published. Iterate until opa test is green.

## Files

- `policy.rego` — the starter. Default-deny is set, and the data-driven allow list (`account_tiers`), the method sets (`read_methods`, `write_methods`), the `subject_tier` helper, and the `write_accounts` set comprehension are all provided. The two `allow if` rules are left as a TODO.
- `policy_test.rego` — the graded test suite: three allow cases and three deny cases. Do not edit it; it defines what "done" means.

## The exercise

Open `policy.rego` and replace the `# TODO(learner)` stub with the two decision rules the policy needs. Multiple `allow if` rules are a logical OR, so write them as two separate rules:

1. **Read access** — a read-tier _or_ write-tier account may call a read method (`GET`, `HEAD`). Use the `subject_tier` helper and the `in` operator against `read_methods`.
2. **Write access** — only a write-tier account may call a write method (`POST`, `PUT`, `DELETE`). Use membership in `write_accounts` and the `in` operator against `write_methods`.

An account that is not a key in `account_tiers` makes `subject_tier` undefined, so those requests fall through to the default deny with no extra code.

### What the tests check

- Allow cases: a write account can `POST`, a write account can read (`HEAD`), a read account can `GET`.
- Deny cases (these catch a false allow): a read account cannot `POST`, a read account cannot `DELETE`, an unknown account is denied.

## Run

```bash
opa test courses/opa-eopa-fundamentals -v
```

Run from the repository root, or `cd` into this `lab/` directory and run `opa test . -v`.

The starter is **red** on purpose: it reports `PASS: 3/6` because the three allow tests fail while `allow` is still the default `false`. Solutions are not published. Iterate until opa test is green.
