# Lab: A Production Decision at the AI-MCP Gateway

A runnable OPA lab for the "Reference Architectures & Operating in Production" course. It models the decision a Policy Decision Point returns for one production request that reaches an AI-MCP gateway Policy Enforcement Point: an AI agent, carrying a SPIFFE workload identity over mutual TLS, asking to invoke a tool. Real `opa`, no invented tooling.

The policy demonstrates two production properties an architect must get right: a **fail-closed default** (anything not explicitly allowed is denied, including a request with no verified workload mTLS) and a **masking-aware decision** (the policy names the sensitive field the audit layer must redact, and the decision-log mask removes exactly that field).

## Your task

`policy.rego` ships as a starter with the two authorizing rules removed. You author them until the whole suite passes.

Open `policy.rego` and find the `# TODO(learner)` block. As shipped, `reason` only ever falls through to its fail-closed default `"deny-fail-closed"`, so `allow` is always `false` and the two allow-case tests fail. Implement the two incremental `reason := ...` rules:

1. `reason := "same-domain-standard"` when the action is `invoke`, `context.mtls_verified` is `true`, the subject's `trust_domain` equals the resource's `owner_domain`, and the resource `classification` is `"standard"`.
2. `reason := "privileged-tool-approved"` when the same identity conditions hold, the resource `classification` is `"restricted"`, and `context.approval_ref` is non-empty.

`reason` is single-valued, but the two branches are mutually exclusive by `resource.classification` (`"standard"` vs `"restricted"`), so no complete-rule conflict is possible. The `allow` lines, the `default reason`, the redaction obligation, and the `decision` object are already wired for you.

Solutions are not published. Iterate until opa test is green.

## Files

- `policy.rego` — a fail-closed production decision policy that returns a **structured decision** (`allow`, `policy_id`, `reason`, `obligations`). Ships with the two `reason` rules stubbed out for you to implement.
- `mask.rego` — a `system.log.mask` policy that strips the sensitive field (`/input/context/api_token`) from a decision-log event before it is shipped. It masks exactly the pointer the policy names in its obligation.
- `opa-config.yaml` — the decision-log configuration that wires the mask rule into the pipeline (`mask_decision: /system/log/mask`), with the Enterprise OPA `decision_logs.mask` equivalent shown as a modeled example.
- `policy_test.rego` — the graded suite: 2 allow cases, 3 fail-closed deny cases, and 6 masking-aware tests.

## Input shape

```json
{
  "subject": {
    "spiffe_id": "spiffe://prod.enforceauth/agent/support-bot",
    "trust_domain": "prod.enforceauth",
    "assurance": "mtls"
  },
  "action": "invoke",
  "resource": {
    "tool": "notes.read",
    "classification": "standard",
    "owner_domain": "prod.enforceauth"
  },
  "context": { "mtls_verified": true, "api_token": "sk-live-abc123" }
}
```

## Rules to implement

- Same-domain standard: a workload may `invoke` a `standard` tool when its workload mTLS is verified and it belongs to the same trust domain that owns the tool.
- Privileged tool with approval: a `restricted` tool may be invoked under the same identity conditions, but only with a non-empty `approval_ref`.
- Everything else falls through to the fail-closed default deny.

## What the tests check

- `test_same_domain_standard_allowed`, `test_privileged_tool_with_approval_allowed` — the allow cases. **Both fail until you implement the two `reason` rules.**
- `test_cross_trust_domain_denied`, `test_missing_mtls_denied`, `test_restricted_tool_without_approval_denied` — the fail-closed deny cases that catch a rule that is too permissive. A cross-domain caller, an unverified-mTLS caller, and a restricted tool with no approval are all denied.
- `test_decision_does_not_leak_token`, `test_policy_flags_token_for_redaction` — the decision object carries no secret, and the policy names `redact:/input/context/api_token` in its obligations. Pass out of the box.
- `test_mask_selects_api_token`, `test_mask_redacts_token_from_event`, `test_mask_preserves_decision_fields` — the mask selects the token pointer, redaction actually removes it from the shipped event, and the identity and result survive. Pass out of the box.
- `test_every_redaction_obligation_is_masked` — the masking-aware check: every pointer the policy flags for redaction is actually removed by the mask. Pass out of the box.

Leave `mask.rego` intact so the masking tests keep passing.

## Fail-closed in one line

The two deny tests `test_cross_trust_domain_denied` and `test_missing_mtls_denied` are the point of a fail-closed default. Neither request matches an authorizing `reason`, so `reason` falls to `deny-fail-closed` and `allow` stays `false`. A gateway that fails closed denies the request it cannot positively authorize, rather than letting it through. See Lesson 3 for where fail-open is instead the right call.

## Masking

`data.system.log.mask` is evaluated over each decision-log event. The whole event is its `input`, so the original decision input is at `input.input`. The rule returns the JSON pointer `/input/context/api_token`, which OPA removes. The identity and result are left intact so the log stays useful as evidence. Enterprise OPA offers the same masking through its `decision_logs.mask` configuration (see `opa-config.yaml`).

The suite proves masking three ways. `test_mask_selects_api_token` checks the mask set. `test_mask_redacts_token_from_event` applies the mask with `json.remove` and asserts the token is actually gone. `test_every_redaction_obligation_is_masked` closes the loop: it asserts that every field the policy flags for redaction is a field the mask removes, so policy and audit cannot drift apart.

## Configuring masking

Masking is turned on by pointing the decision-log plugin at the mask rule. In `opa-config.yaml`:

```yaml
decision_logs:
  console: true
  mask_decision: /system/log/mask
```

`mask_decision` defaults to `/system/log/mask`, the fully-qualified path of the `mask` rule in `mask.rego` (package `system.log`). Enterprise OPA exposes the same masking through `decision_logs.mask` as a managed pipeline stage; the file models that config as the same JSON pointer.

## Run

Run from the repo root:

```bash
opa test courses/reference-architectures -v
```

The starter reports `FAIL: 2/11`. Solutions are not published. Iterate until opa test is green.

## Going further

Once the suite is green, try extending it:

1. Add a second sensitive field to the input (for example `context.prompt`), mask its pointer in `mask.rego`, and add the matching redaction obligation to `policy.rego`. `test_every_redaction_obligation_is_masked` should still pass, because policy and mask stay in sync.
2. Add a deny test proving a workload with `assurance` other than `mtls` cannot invoke, then tighten the rules to enforce it. Decide whether that denial should be fail-closed (deny) or fail-open (allow with an obligation) and justify it against Lesson 3.
3. Break the loop on purpose: remove the token pointer from `mask.rego` but leave the obligation in `policy.rego`. Watch `test_every_redaction_obligation_is_masked` fail. That test is what stops a policy from claiming a field is redacted when the audit layer never scrubs it.
