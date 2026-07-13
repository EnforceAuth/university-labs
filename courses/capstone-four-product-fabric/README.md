# Lab: Assemble the AI Security Fabric

The capstone lab. One Rego policy stands in for the whole fabric working
together: Zift extracted it from application code, Writ governs and promotes it,
the PDP (OPA or Enterprise OPA) evaluates it, Herald exposes the query and
federates the context that fills `input`, and decision logs plus masking close
the loop. Real `opa`, no invented tooling. Writ, Herald, and Zift are not local
CLIs you run here; this lab is the artifact they operate on.

## Files

- `policy.rego` — the extracted-then-governed customer-records policy. It ships
  as a **starter**: `role_permissions` (the map Zift extracted) and the
  structured `decision` are wired for you, but the three `allow` rules are
  stubbed behind a `TODO(learner)` block, so the suite starts red. You author
  the rules.
- `mask.rego` — a `system.log.mask` policy (package `system.log`) that strips
  the subject SSN and the resource card number from a decision-log event. This
  is already complete; the mask tests pass from the start.
- `policy_test.rego` — the graded suite: three allow cases, four deny cases, and
  four masking cases. Do not edit it; it defines the target behavior.

## Your exercise

Open `policy.rego` and implement the three `allow` rules the `TODO(learner)`
block describes so all eleven tests pass. Every rule requires an active employee
(`input.subject.employment_status == "active"`). The rules to author:

1. **Role + tenancy** — the subject's role permits the action
   (`input.action in role_permissions[input.subject.role]`), the subject is in
   the resource's org (`input.subject.org == input.resource.org`), and the
   resource is below restricted
   (`input.resource.classification in {"public", "internal"}`).
2. **Ownership** — the action is `read` or `write` and the subject owns the
   record (`input.resource.owner_id == input.subject.id`), regardless of org. Do
   not allow `delete` on this path; delete stays role-gated.
3. **Restricted** — same as rule 1 but for a restricted record
   (`input.resource.classification == "restricted"`) the subject also needs an
   approved change ticket
   (`input.context.change_ticket.status == "approved"`). That change-ticket
   status is the ITSM signal Herald federates into `input.context`.

Write these as incremental `allow if { ... }` rules that OR together on top of
`default allow := false`. Use the `in` operator for the action and
classification checks.

## Input shape

```json
{
  "subject": {
    "id": "u1",
    "role": "editor",
    "org": "acme",
    "employment_status": "active",
    "ssn": "111-22-3333"
  },
  "action": "export",
  "resource": {
    "kind": "record",
    "org": "acme",
    "owner_id": "u9",
    "classification": "internal",
    "card_number": "4111111111111111"
  },
  "context": { "change_ticket": { "status": "none" } }
}
```

## What the tests check

- **Three allow tests** assert the three grant paths: an active editor exporting
  an internal record in their own org (role + tenancy), an active viewer reading
  a record they own in another org (ownership), and an active admin reading a
  restricted record with an approved change ticket (restricted + ITSM).
- **Four deny tests** catch a false allow: an editor writing across orgs, a
  terminated employee, a restricted record without approval, and a viewer trying
  to delete. These are the tests a Writ promotion gate relies on to block a bad
  bundle.
- **Four masking tests** exercise `mask.rego` over a decision-log event: the
  SSN and card number are selected and actually removed, while the org, the
  classification, and the decision result survive so the log is still evidence.

## Run

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
opa test courses/capstone-four-product-fabric -v
```

Starter state: `FAIL: 3/11` (the three allow tests fail until you implement the
rules; the deny and mask tests already pass). Target: `PASS: 11/11`. Keep
iterating until `opa test` is green.

## How the four products assemble around this file

This lab does not run Zift, Writ, or Herald (they are not local CLIs). It shows
the one artifact they all operate on. In a real deployment:

1. **Zift** scans the application, finds the authorization embedded in code, and
   `zift extract` produces this default-deny `policy.rego`. The externalization
   percentage tells you how much of the app's authorization is now here.
2. **Writ** governs the file from Git: on merge it auto-builds a **signed
   bundle**, scopes it to an entity (tenant, org, system, app), and promotes it
   **dev to staging to prod** with the same signed bytes. Rollback redeploys a
   prior `commit_sha`.
3. The **PDP** (OPA or Enterprise OPA) pulls the bundle at the PEP and evaluates
   this policy on every request. `opa test` here plays the PDP.
4. **Herald** exposes the same authorization query over MCP and federates the
   context (the ITSM change-ticket status, the HRIS employment status) that
   fills `input`. Herald is the MCP server, not the PDP.
5. **Decision logs + replay** close the loop. `mask.rego` keeps the SSN and card
   number out of the log; Writ replay re-runs recorded inputs against a
   candidate bundle before you promote it. (**Verdict**, coming soon, would add a
   human-in-the-loop approval obligation on top.)

## Going further

Once the suite is green, model a Verdict-style obligation: add an
`obligations contains "require-human-approval"` rule that fires when an admin
`export`s a restricted record, then add one test asserting the obligation
appears and one asserting a plain internal read carries no obligation. That is
the seam where the agentic firewall will plug in.
