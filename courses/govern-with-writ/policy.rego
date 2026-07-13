package university.writ.docs_authz

# A teaching policy for the "Govern with Writ" course. It models the decision a
# Policy Decision Point (PDP) such as OPA or Enterprise OPA returns for a single
# request against a document service. This is standard OPA/Rego and runs on the
# PDP at request time.
#
# In the course, this is the policy artifact Writ governs: Writ signs it into a
# bundle from Git, promotes that bundle dev -> staging -> prod, and keeps decision
# logs with replay. Writ is EnforceAuth's control plane; it is not a PDP and is
# not on the request path. The policy below is what the PDP actually evaluates.
#
# Input shape:
#   {
#     "subject":  {"role": "admin" | "editor" | "viewer", "org": "<org id>"},
#     "action":   "read" | "write" | "delete",
#     "resource": {"kind": "document", "org": "<owning org id>"}
#   }
#
# Rules modeled:
#   - Admins may perform any action on any document.
#   - Editors may read or write a document owned by their own org
#     (subject.org == resource.org).
#   - Viewers may read a document owned by their own org.
# Everything else falls through to the default deny.

default allow := false

# TODO(learner): implement the authorization rules.
#
# This starter is default-deny only, so every allow test in policy_test.rego
# currently fails. Author incremental `allow if { ... }` rules that OR together
# on top of the default above until the whole suite passes:
#   - Admins may perform any action on any document.
#   - Editors may read or write a document owned by their own org
#     (input.subject.org == input.resource.org).
#   - Viewers may read a document owned by their own org.
# Everything else must fall through to the default deny.
#
# Hints:
#   - Each rule is `allow if { <conditions> }`; the conditions are ANDed, and
#     separate allow rules OR together.
#   - Use the `in` operator for the action check, e.g.
#     input.action in {"read", "write"}.
#
# Run `opa test courses/govern-with-writ -v`
# Solutions are not published. Iterate until opa test is green.
