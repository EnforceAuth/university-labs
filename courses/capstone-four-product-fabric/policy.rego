package university.capstone.authz

# Capstone teaching policy: the extracted-then-governed policy the AI Security
# Fabric enforces end to end. It models the decision a Policy Decision Point
# (OPA or Enterprise OPA) returns for one request against a customer-records
# service. This is standard OPA/Rego and runs on the PDP at request time.
#
# How the four products assemble around this one file:
#   - Zift SCANNED the application, found the authorization embedded in code (a
#     requireRole(...) middleware, an inline `if user.role == "admin"` on
#     delete, and an ownership guard `if rec.owner_id == user.id`), and
#     `zift extract` turned those checks into the default-deny policy below.
#   - Writ GOVERNS this file from Git: on merge it auto-builds a signed bundle,
#     promotes it dev -> staging -> prod unchanged, and keeps decision logs with
#     replay. Writ is the control plane; it is not a PDP and is not on the
#     request path.
#   - The PDP (OPA / Enterprise OPA) EVALUATES this policy at the PEP.
#   - Herald EXPOSES the same query over MCP and federates the context that
#     fills `input.context` (here, an ITSM change-ticket status). Herald is the
#     authorization MCP server; it is not the PDP.
#   - Decision logs + replay CLOSE THE LOOP. The companion mask.rego keeps the
#     sensitive fields out of those logs. (Verdict, coming soon, would add
#     human-in-the-loop approval as an agentic-firewall obligation.)
#
# Input shape:
#   {
#     "subject": {
#       "id": "<user id>",
#       "role": "viewer" | "editor" | "admin",
#       "org": "<org id>",
#       "employment_status": "active" | "terminated",   # HRIS, federated by Herald
#       "ssn": "<sensitive, masked from logs>"
#     },
#     "action":   "read" | "write" | "export" | "delete",
#     "resource": {
#       "kind": "record",
#       "org": "<owning org id>",
#       "owner_id": "<user id who owns the record>",
#       "classification": "public" | "internal" | "restricted",
#       "card_number": "<sensitive, masked from logs>"
#     },
#     "context": {
#       "change_ticket": {"status": "approved" | "pending" | "none"}   # ITSM, federated by Herald
#     }
#   }

default allow := false

# Zift extracted this role -> actions map from the requireRole(...) middleware
# and the inline role comparisons in the application code. This part is done for
# you; use it in the rules you author below.
role_permissions := {
	"viewer": {"read"},
	"editor": {"read", "write", "export"},
	"admin": {"read", "write", "export", "delete"},
}

# TODO(learner): implement the three authorization rules the fabric enforces.
#
# This starter is default-deny only, so every allow test in policy_test.rego
# currently fails while the deny tests and the mask tests already pass. Author
# incremental `allow if { ... }` rules that OR together on top of the default
# above until the whole suite passes. Every rule requires an active employee
# (input.subject.employment_status == "active").
#
#   1) Role + tenancy: the subject's role permits the action
#        (input.action in role_permissions[input.subject.role]), the subject is
#        in the resource's org (input.subject.org == input.resource.org), and
#        the resource is below "restricted"
#        (input.resource.classification in {"public", "internal"}).
#
#   2) Ownership: the action is "read" or "write" AND the subject owns the
#        record (input.resource.owner_id == input.subject.id). This grant holds
#        regardless of org. Do NOT allow delete on this path; delete stays
#        role-gated by rule 1/3.
#
#   3) Restricted: same as rule 1 but for restricted records
#        (input.resource.classification == "restricted") the subject ALSO needs
#        an approved change ticket
#        (input.context.change_ticket.status == "approved"). This is the ITSM
#        signal Herald federates into input.context.
#
# Hints:
#   - Each rule is `allow if { <conditions> }`; conditions are ANDed within a
#     rule, and separate allow rules OR together.
#   - Use the `in` operator for the action and classification checks.
#
# Run `opa test courses/capstone-four-product-fabric -v`
# Solutions are not published. Iterate until opa test is green.

# The structured decision the PDP emits and the decision log records. This is
# the object Writ collects and can replay; mask.rego strips the sensitive
# fields from the surrounding log event before it ships.
decision := {
	"allow": allow,
	"policy_id": "customer-records-v1",
}
