# Lab: Structured Decisions and Decision-Log Masking

A runnable OPA lab for the "Decision Logs, Continuous Authorization & Compliance Evidence" course. Real `opa`, no invented tooling.

## Your task

`policy.rego` ships as a starter with the core decision logic removed. You author the two authorizing rules until the whole suite passes.

Open `policy.rego` and find the `# TODO(learner)` block. As shipped, `reason` only ever falls through to its default `"deny-no-authorization"`, so `allow` is always `false` and the two allow-case tests fail. Implement the two incremental `reason := ...` rules:

1. `reason := "care-team-match"` when the action is `read` and the record's `care_team` is one of the subject's `care_teams` (a minimum-necessary style check). Use the `in` operator for the membership test.
2. `reason := "break-glass"` when the action is `read`, the subject's `role` is `emergency`, the `context.justification` is non-empty, and the record's `care_team` is **not** one of the subject's `care_teams` (an emergency override).

`reason` is single-valued. Guard the break-glass body with the negated membership check so the two rules cannot both fire on one input; otherwise OPA reports a complete-rule conflict. The `allow` lines and the `default reason` are already wired for you.

Solutions are not published. Iterate until opa test is green.

## Files

- `policy.rego` — a default-deny clinical-access policy that returns a **structured decision** (`allow`, `policy_id`, `reason`, `obligations`), the kind of object worth recording in a decision log. Ships with the two `reason` rules stubbed out for you to implement.
- `mask.rego` — a `system.log.mask` policy that strips sensitive fields (SSN, MRN) from a decision-log event before it is shipped.
- `opa-config.yaml` — the decision-log configuration that wires the mask rule into the pipeline (`mask_decision: /system/log/mask`), with the Enterprise OPA `decision_logs.mask` equivalent shown as a modeled example.
- `policy_test.rego` — the graded suite: 2 allow cases, 3 deny cases, and 4 masking tests (2 asserting the mask set, 2 asserting the event is actually redacted).

## Input shape

```json
{
  "subject": {
    "id": "u1",
    "role": "clinician",
    "care_teams": ["cardiology"],
    "ssn": "123-45-6789"
  },
  "action": "read",
  "resource": { "type": "record", "care_team": "cardiology", "mrn": "MRN-88" },
  "context": { "justification": "" }
}
```

## Rules to implement

- A clinician may `read` a record when the record's `care_team` is one of the subject's `care_teams` (minimum-necessary style).
- Break-glass: an `emergency` clinician not on the care team may `read` with a non-empty `justification`, and the decision then carries the obligation `notify-privacy-officer`.
- Everything else falls through to the default deny.

## What the tests check

- `test_care_team_member_can_read` — a care-team clinician is allowed, `decision.reason == "care-team-match"`, and there are no obligations. **Fails until you implement the care-team rule.**
- `test_break_glass_allows_with_justification` — an emergency clinician off the care team with a justification is allowed, `decision.reason == "break-glass"`, and `decision.obligations` contains `notify-privacy-officer`. **Fails until you implement the break-glass rule.**
- `test_non_care_team_clinician_denied`, `test_break_glass_denied_without_justification`, `test_write_action_denied` — the deny cases that catch a rule that is too permissive.
- The four masking tests exercise `mask.rego` and pass out of the box; leave `mask.rego` intact so they keep passing.

## Masking

`data.system.log.mask` is evaluated over each decision-log event. The whole event is its `input`, so the original decision input is at `input.input`. The rule returns JSON pointers that OPA removes: `/input/subject/ssn` and `/input/resource/mrn`. The care team and result are left intact so the log stays useful as evidence. Enterprise OPA offers the same masking through its `decision_logs.mask` configuration (see `opa-config.yaml`).

The suite proves this two ways. `test_mask_selects_ssn_and_mrn` checks the mask set. `test_mask_redacts_ssn_and_mrn_from_event` then applies the mask with `json.remove` and asserts the SSN and MRN are actually gone from the shipped event, while `test_mask_preserves_care_team_and_result_after_redaction` asserts the care team and result survive.

## Configuring masking

Masking is turned on by pointing the decision-log plugin at the mask rule. In `opa-config.yaml`:

```yaml
decision_logs:
  console: true
  mask_decision: /system/log/mask
```

`mask_decision` defaults to `/system/log/mask`, which is the fully-qualified path of the `mask` rule in `mask.rego` (package `system.log`). Enterprise OPA exposes the same masking through `decision_logs.mask` as a managed pipeline stage; the file models that config as a list of the same JSON pointers.

## Run

Run from the repo root:

```bash
opa test courses/decision-logs-and-compliance-evidence -v
```

The starter reports `FAIL: 2/9`. Solutions are not published. Iterate until opa test is green.

## Going further

Once the suite is green, try extending it:

1. Add a rule to `mask.rego` that also masks `/input/subject/id`, then add a test asserting that pointer is in the mask set.
2. Add a deny test proving a clinician on a different care team still cannot `read`.
3. Keep the suite green. If a masking change accidentally strips `/input/resource/care_team`, the `test_mask_does_not_select_care_team_or_result` and `test_mask_preserves_care_team_and_result_after_redaction` guards should fail. Over-masking destroys evidence, and those tests catch it.
