package university.prod.authz

# A teaching policy for the "Reference Architectures & Operating in Production"
# course. It models the decision a Policy Decision Point (OPA or Enterprise OPA)
# returns for one production request that reaches an AI-MCP gateway Policy
# Enforcement Point. The request is a workload (an AI agent) asking to invoke a
# tool, carrying a SPIFFE workload identity established over mutual TLS.
#
# This is the request path: the PEP asks the PDP, the PDP returns this decision.
# EnforceAuth's Writ control plane governs how THIS policy shipped (built and
# signed from Git, scoped to one app in the entity hierarchy, replayed before
# promotion). Writ is not a PDP and is not on the request path.
#
# The policy demonstrates two production properties an architect must get right:
#
#   1. Fail-closed default. `default allow := false`, and `reason` defaults to
#      "deny-fail-closed". Anything the rules do not explicitly allow is denied,
#      including a request that arrives without verified workload mTLS. When the
#      PDP is uncertain, it denies. That is the safe direction for a gateway.
#
#   2. Masking-aware decision. The policy never copies the caller's secret into
#      its decision object, and it emits an obligation naming the sensitive field
#      the audit layer must redact from decision logs. The decision_logs mask
#      (mask.rego) then removes exactly that field. Policy and audit agree on
#      what is sensitive.
#
# Input shape:
#   {
#     "subject":  {"spiffe_id": "...", "trust_domain": "...", "assurance": "..."},
#     "action":   "invoke",
#     "resource": {"tool": "...", "classification": "standard"|"restricted", "owner_domain": "..."},
#     "context":  {"mtls_verified": true, "api_token": "...", "approval_ref": "..."}
#   }
#
# Rules modeled:
#   - Same-domain standard: a workload may invoke a STANDARD tool when its
#     workload mTLS is verified and it belongs to the same trust domain that owns
#     the tool.
#   - Privileged tool with approval: a RESTRICTED tool may be invoked under the
#     same identity conditions, but only with a non-empty approval reference.
# Everything else falls through to the fail-closed default deny.

default allow := false

# The request is allowed exactly when the policy produced an authorizing reason.
# These two lines are already wired for you; your job is to make `reason` take
# the right value below.
allow if reason == "same-domain-standard"

allow if reason == "privileged-tool-approved"

# TODO(learner): implement the two authorizing `reason` rules.
#
# Right now `reason` only ever falls through to the fail-closed default
# "deny-fail-closed" below, so `allow` is always false and the two allow-case
# tests fail. Add the incremental `reason := ...` rules that make them pass.
#
#   1) reason := "same-domain-standard" when:
#        - input.action == "invoke"
#        - input.context.mtls_verified == true
#        - input.subject.trust_domain == input.resource.owner_domain
#        - input.resource.classification == "standard"
#
#   2) reason := "privileged-tool-approved" when (restricted tool + approval):
#        - input.action == "invoke"
#        - input.context.mtls_verified == true
#        - input.subject.trust_domain == input.resource.owner_domain
#        - input.resource.classification == "restricted"
#        - input.context.approval_ref != ""
#
# `reason` is single-valued. The two branches are mutually exclusive by
# resource.classification ("standard" vs "restricted"), so no complete-rule
# conflict is possible. Keep iterating until `opa test` is green.
# if you get stuck.

# Fail-closed: no authorizing reason means deny. This default is what makes an
# unverified or unknown request deny rather than leak through.
default reason := "deny-fail-closed"

# Masking-aware obligation. When the request carries an api_token, the policy
# declares the JSON pointer the audit layer must redact from the decision log.
# The decision itself (below) never contains the token, and mask.rego removes
# exactly this pointer, so the secret is named once and scrubbed everywhere.
obligations contains "redact:/input/context/api_token" if {
	input.context.api_token
}

# The structured decision worth logging: outcome, policy id, reason, and the
# redaction obligations. Note that no field of `input.context` is copied in, so
# the token cannot leak through the decision object.
decision := {
	"allow": allow,
	"policy_id": "mcp-gateway-authz-v1",
	"reason": reason,
	"obligations": obligations,
}
