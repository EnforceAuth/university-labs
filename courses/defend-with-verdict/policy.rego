package university.verdict.approvals

# A teaching policy for the "Defend with Verdict (Agentic Firewall)" course.
# It models the authorization decision that gates a sensitive agent action:
# a low-risk action runs on its own, but a high-risk action is denied unless it
# carries a valid human-in-the-loop approval.
#
# This is standard OPA/Rego evaluated by a Policy Decision Point (OPA or
# Enterprise OPA). Verdict, EnforceAuth's agentic firewall, is the product that
# would enforce a gate like this at runtime, hold the action pending a human
# decision, and inject a short-lived identity so the agent never holds the
# upstream credential. Verdict is "coming soon" and not yet generally available;
# this lab models only the policy decision it depends on, in plain OPA.
#
# Input shape:
#   {
#     "agent":    {"id": "..."},
#     "action":   {"name": "...", "risk": "low" | "high"},
#     "resource": {"kind": "..."},
#     "approval": {
#       "present":       true | false,
#       "approver_type": "human" | "agent",
#       "approver":      "...",
#       "scope_action":  "<the exact action this approval authorizes>",
#       "expires_at":    <unix seconds>
#     },
#     "now": <unix seconds>
#   }
#
# Rules modeled:
#   - A low-risk action from a recognized agent needs no approval.
#   - A high-risk (sensitive) action is allowed only with a valid approval:
#       a human (not the agent) approved this exact action and it has not expired.
# Everything else falls through to the default deny.

default allow := false

# TODO(learner): implement the approval gate so all seven tests in
# policy_test.rego pass. Right now the policy denies everything (default deny),
# so the three allow tests fail. Add the rules below, then run:
#   opa test courses/defend-with-verdict -v
#
# 1. Low-risk (read-only) actions from a recognized agent run without a human
#    gate. Add an `allow if { ... }` rule that permits an action when
#    input.action.risk == "low" and the agent has a non-empty id.
#
# 2. Sensitive (high-risk) actions are allowed only with a valid human approval.
#    Add an `allow if { ... }` rule that permits a high-risk action when
#    `valid_approval` holds.
#
# 3. Define `valid_approval` so an approval counts only when ALL of these hold:
#      - the approval is present (input.approval.present == true)
#      - a human approved it, never the agent (approver_type == "human")
#      - it authorizes THIS exact action (scope_action == input.action.name)
#      - it has not expired (expires_at > input.now)
#    The human-approver check is what closes off the Politeness Trap: an agent
#    must never be able to approve its own sensitive action.
#
# Solutions are not published. Iterate until opa test is green.
# first, then compare.
