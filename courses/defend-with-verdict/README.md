# Lab: Gating a Sensitive Agent Action

A runnable OPA lab for the "Defend with Verdict (Agentic Firewall)" course. Real `opa`, no invented tooling.

Verdict is EnforceAuth's agentic firewall. It is "coming soon" and not yet generally available, so this lab does not run Verdict. It models, in plain OPA, the authorization decision Verdict depends on: allow a low-risk agent action, but deny a sensitive one unless it carries a valid human-in-the-loop approval.

## Your task

`policy.rego` ships as a starter that denies everything (`default allow := false`). Your job is to implement the approval gate marked `# TODO(learner)` so all seven tests in `policy_test.rego` pass. Do not edit `policy_test.rego`.

You need to add three things:

1. An `allow` rule for low-risk actions: a `low` risk action from an agent with a non-empty id runs without a human gate.
2. An `allow` rule for high-risk actions: a `high` risk action is allowed only when `valid_approval` holds.
3. The `valid_approval` rule itself, true only when **all four** properties hold:
   - the approval is present,
   - a human (not the agent) approved it,
   - it authorizes this exact action (scope matches `input.action.name`),
   - it has not expired (`expires_at > input.now`).

The human-approver check is what closes off the Politeness Trap: an agent must never approve its own sensitive action.

## What the tests check

`policy_test.rego` is the graded suite: three allow cases and four deny cases.

- Allow: a low-risk action with no approval; a high-risk action with a valid human approval; a second high-risk action with a scoped approval.
- Deny: high-risk with no approval (presence); high-risk with an agent self-approval (human approver); high-risk with a scope mismatch (scope); high-risk with an expired approval (expiry).

The deny tests are the point: each one names a way a bad action could slip through. If your policy ever lets a high-risk action through without a valid human approval, a deny test fails.

## Input shape

```json
{
  "agent": { "id": "agent-legal-assistant" },
  "action": { "name": "send_wire_transfer", "risk": "high" },
  "resource": { "kind": "payment" },
  "approval": {
    "present": true,
    "approver_type": "human",
    "approver": "cfo@example.com",
    "scope_action": "send_wire_transfer",
    "expires_at": 2000
  },
  "now": 1000
}
```

## Run

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
opa test courses/defend-with-verdict -v
```

The starter fails 3 of 7 (the allow cases). When your implementation is correct you will see `PASS: 7/7`.

Implement the starter until `opa test` is green. This lab is practice for the machine-graded certification, which runs your policy against a hidden test suite you do not see.
