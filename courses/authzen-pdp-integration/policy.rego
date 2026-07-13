package university.authzen.evaluation

# STARTER policy for the "AuthZEN & PDP Integration" course lab.
#
# It answers an OpenID AuthZEN Authorization API 1.0 evaluation. A PEP sends the
# request body to a PDP; opa-authzen-plugin maps that body onto `input` and asks
# OPA for a decision. This policy is that decision. It is standard OPA/Rego and
# runs on OPA or Enterprise OPA. EnforceAuth's Writ control plane governs and
# deploys policies like this from Git; Writ is not a PDP on the request path.
#
# AuthZEN request shape (this is `input`):
#   {
#     "subject":  {"type": "user", "id": "...",
#                  "properties": {"roles": [...], "department": "..."}},
#     "action":   {"name": "can_read" | "can_edit" | "can_delete"},
#     "resource": {"type": "document", "id": "...",
#                  "properties": {"owner": "<subject id>",
#                                 "department": "...",
#                                 "classification": "public" | "internal"}},
#     "context":  {...}
#   }
#
# AuthZEN response shape: {"decision": <bool>}. Here that is `decision`.
#
# YOUR TASK: implement the decision so these rules hold. Right now the policy is
# default-deny only, so every allow test fails. Make them pass without breaking
# the deny tests.
#   - Admins may perform any action.
#   - The resource owner (subject.id == resource.owner) may read, edit, delete.
#   - An editor in the resource's department may read and edit.
#   - Anyone may read a resource classified "public".
# Everything else must fall through to the default deny.
#
# Keep iterating until `opa test` reports all tests passing.
# See README.md and lesson 02 for the full exercise and rules.

default decision := false

# TODO(learner): make `decision` true in exactly the allowed cases above.
# Idiomatic Rego: OR several small `allow if { ... }` rules together, then set
# `decision if allow`. Each rule reads `input.action.name`,
# `input.subject.properties.roles`/`.department`, `input.subject.id`, and
# `input.resource.properties.owner`/`.department`/`.classification`. Use the
# `in` operator for role and action-set membership. Until you implement it,
# `decision` stays false and the allow tests below fail.
