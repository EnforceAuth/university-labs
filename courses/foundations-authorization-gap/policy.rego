package university.foundations.authz

# A teaching policy for the "AI Security Fabric & the Authorization Gap" course.
# It models the decision a Policy Decision Point (PDP) such as OPA or Enterprise
# OPA returns for a single request. This is standard OPA/Rego. EnforceAuth's
# Writ control plane governs and deploys policies like this from Git; Writ is not
# a PDP on the request path.
#
# Input shape:
#   {
#     "subject":  {"role": "...", "department": "..."},
#     "action":   "read" | "write" | "delete",
#     "resource": {"kind": "...", "owner": "<owning department>"}
#   }
#
# Rules modeled:
#   - Admins may delete any resource.
#   - Owners may delete a resource their department owns
#     (subject.department == resource.owner).
#   - Members may read.
# Everything else falls through to the default deny.

default allow := false

# TODO(learner): implement the three allow rules below so the tests in
# policy_test.rego pass. This starter is default-deny only, so every request
# is currently denied and the three allow tests FAIL. That is expected.
#
# Add one `allow if { ... }` rule for each case (multiple rules with the same
# name are a logical OR). Keep iterating until `opa test` is green.
#
# 1. Admins may delete any resource.
#      input.action == "delete" and input.subject.role == "admin"
#
# 2. Owners may delete a resource their department owns.
#      input.action == "delete" and input.subject.department == input.resource.owner
#
# 3. Members may read.
#      input.action == "read" and input.subject.role == "member"
#
# Run: opa test courses/foundations-authorization-gap -v
