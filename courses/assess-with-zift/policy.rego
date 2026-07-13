package university.zift.authz

# Extracted authorization for a document service (STARTER — you complete it).
#
# Zift found the authorization logic below scattered across the application
# code: a `requireRole(...)` middleware on the write and delete handlers, an
# inline `if user.role == "admin"` check guarding delete, and an ownership
# guard `if doc.owner_id == user.id` on the read/write path. `zift extract`
# turned those embedded checks into a single default-deny Rego policy so a
# PDP (OPA or Enterprise OPA) can make the decision instead of the app.
#
# This starter ships the default-deny base and the extracted role table. The
# two `allow` decision rules have been removed and left as a TODO for you to
# implement. Run `opa test` against this directory to see which tests fail,
# implement the rules, and get back to green. The reference solution lives in
# Solutions are not published. Iterate until opa test is green.
#
# This is standard OPA/Rego. Writ (EnforceAuth's control plane) governs and
# deploys policies like this from Git; it is not a PDP on the request path.

default allow := false

# Role -> the set of actions that role may perform. Extracted from the
# `requireRole(...)` middleware and the inline role comparisons.
role_permissions := {
	"viewer": {"read"},
	"editor": {"read", "write"},
	"admin": {"read", "write", "delete"},
}

# TODO(learner): implement the two extracted decision paths so the suite in
# policy_test.rego passes. Add them as incremental `allow if` rules that OR
# together on top of the `default allow := false` base above.
#
#   1. Role-based path: allow when the requested action is in the set of
#      actions permitted for the subject's role. Look the role up in
#      `role_permissions` with `input.subject.role`, and use the `in`
#      operator to test `input.action` against that set. An unknown role
#      leaves the lookup undefined, so `allow` stays false — that is the
#      point of default-deny.
#
#   2. Ownership path: allow a `read` or `write` (NOT `delete`) when the
#      subject owns the resource, i.e. `input.resource.owner_id` equals
#      `input.subject.id`. Delete stays role-gated on purpose: owning a
#      document does not let you delete it.
#
# Until you add these rules, `allow` is always false: every allow test fails
# Solutions are not published. Iterate until opa test is green.
