# Lab: Modeling a Herald Authorization Query

A runnable OPA lab for the "Evaluate with Herald" course. Real `opa`, no invented tooling.

Herald is the authorization MCP server: it fronts a decision like this one as an MCP tool and federates the context that fills `input`. The decision itself is evaluated by a PDP (OPA or Enterprise OPA), which is what this lab runs. The lab does not run Herald; it grades the underlying policy.

## Your task

`policy.rego` ships as a **starter**: the two `allow` rules are stubbed out with a `# TODO(learner)` block, so the policy currently allows nothing and three of the eight tests FAIL. Author the two allow paths until `opa test` is green.

- **Rule 1 — non-restricted read.** Allow when the action is a read action (`read`/`query`), the subject is an `active` employee (HRIS), is in an authorized group (IdP), and the dataset is `public` or `internal` (warehouse).
- **Rule 2 — restricted read.** Same as Rule 1 for a `restricted` dataset, plus two federated gates: a `low`/`medium` SIEM risk level and an `approved` ITSM change ticket.

Write each as its own `allow if { ... }` block; the two rules OR together. A mutating action (`write`, `export`) must never reach an allow, so leave it to `default allow := false`.

## Files

- `policy.rego` — starter policy with a default deny and the two allow rules left as a TODO for you to implement.
- `policy_test.rego` — the graded test suite: three allow cases and five deny cases. Do not edit it.

Solutions are not published. Iterate until opa test is green.

## Input shape

```json
{
  "subject": { "idp_groups": ["analysts"], "employment_status": "active" },
  "action": "query",
  "resource": { "dataset": "revenue", "classification": "restricted" },
  "context": {
    "change_ticket": { "status": "approved" },
    "risk": { "level": "low" }
  }
}
```

Each field is federated from a system of record. These five sources are the example set this lab uses, not a fixed product taxonomy:

| `input` field                  | Source    | Question it answers                 |
| ------------------------------ | --------- | ----------------------------------- |
| `subject.idp_groups`           | IdP       | What groups does the subject hold?  |
| `subject.employment_status`    | HRIS      | Is the subject an active employee?  |
| `resource.classification`      | Warehouse | How sensitive is the dataset?       |
| `context.change_ticket.status` | ITSM      | Is there an approved change ticket? |
| `context.risk.level`           | SIEM      | How risky does the session look?    |

## Rules

- Only read-style actions (`read`, `query`) can be allowed. This models a read-only scope for the Herald tool (a teaching model this course adopts, not a stated product tier); mutating actions fall through to the default deny.
- An active employee in an authorized group may read a `public` or `internal` dataset.
- A `restricted` dataset additionally requires a low or medium SIEM risk level and an approved ITSM change ticket.
- Everything else falls through to the default deny.

## Run

```bash
opa test courses/evaluate-with-herald -v
```

Run it from the repo root (the path is repo-root-relative). On the starter you will see `FAIL: 3/8` (the three allow tests). When you finish the TODO the target is `PASS: 8/8`.

## Once you are green

After the two allow rules pass, try extending the policy to cement the read-only scope:

1. Add an `export` action to a scenario and write a deny test proving even an active, authorized analyst is denied `export`, because it is not a read action.
2. Add a second read action (for example `search`) to the policy's read-action set, then add one allow test for a `search` on an `internal` dataset.
3. Keep the suite green. If a change lets a mutating action through, a deny test must fail. That is the point: the deny tests are the guardrail on the read-only scope.
