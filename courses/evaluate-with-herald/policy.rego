package university.herald.authz

# A teaching policy for the "Evaluate with Herald" course. It models the
# decision that a Herald authorization tool exposes over MCP for one federated
# query. This is standard OPA/Rego. Herald is the MCP server that fronts the
# query and federates the context that fills `input`; the decision itself is
# evaluated by a PDP, OPA or Enterprise OPA, which is what `opa test` exercises
# here. Herald is not the PDP and is not the Writ control plane.
#
# The `input` document is a query Herald joins from several systems of record.
# The five sources below are the example set this lab uses, not a fixed product
# taxonomy; a real deployment federates whatever systems you connect:
#   - IdP       -> subject.idp_groups        (groups the subject holds)
#   - HRIS      -> subject.employment_status (active / contractor / terminated)
#   - Warehouse -> resource.classification   (public / internal / restricted)
#   - ITSM      -> context.change_ticket.status (approved / pending / none)
#   - SIEM      -> context.risk.level        (low / medium / high)
#
# Input shape:
#   {
#     "subject":  {"idp_groups": ["..."], "employment_status": "..."},
#     "action":   "read" | "query" | "write" | "export",
#     "resource": {"dataset": "...", "classification": "..."},
#     "context":  {
#       "change_ticket": {"status": "..."},
#       "risk":          {"level": "..."}
#     }
#   }
#
# Scope note: for this course we model a Herald tool that holds a read-only
# scope (a teaching model, not a stated product tier), so only read-style
# actions can be decided. Mutating actions fall through to the default deny.

default allow := false

# The read-only scope we model confines decisions to read-style actions.
read_actions := {"read", "query"}

# The subject is in a group the query authorizes (IdP context).
authorized_group if {
	some g in input.subject.idp_groups
	g in {"analysts", "data-platform"}
}

# TODO(learner): implement the two allow rules that model the Herald decision.
# Right now nothing sets `allow` to true, so every request falls through to the
# default deny and the three allow tests in policy_test.rego FAIL. Your job is to
# author the allow paths until `opa test` is green.
#
# Rule 1 (non-restricted read): allow when ALL of these hold
#   - input.action is in read_actions           (read-only scope)
#   - input.subject.employment_status == "active" (HRIS: active employee)
#   - authorized_group                            (IdP: analysts or data-platform)
#   - input.resource.classification is "public" or "internal" (warehouse)
#
# Rule 2 (restricted read): same as Rule 1 but for a "restricted" dataset, and
# additionally require BOTH federated gates:
#   - input.context.risk.level is "low" or "medium" (SIEM)
#   - input.context.change_ticket.status == "approved" (ITSM)
#
# Write each as its own `allow if { ... }` block. Multiple allow rules OR
# together, so listing the two cases separately is idiomatic Rego. A mutating
# action (write, export) must never reach an allow: leave it to the default deny.
