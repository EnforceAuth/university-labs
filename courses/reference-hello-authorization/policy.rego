package university.reference.authz

# A minimal, teaching-oriented authorization policy for the reference course.
# It demonstrates the shape every EnforceAuth University lab uses: a default-deny
# decision, data-driven permissions, and a single `allow` rule that a PDP
# (OPA / Enterprise OPA) evaluates. This is standard OPA/Rego. EnforceAuth's
# Writ control plane governs and deploys policies like this; it is not on the
# request path itself.

default allow := false

# Role -> the set of actions that role may perform on a resource.
permissions := {
	"viewer": {"read"},
	"editor": {"read", "write"},
	"admin": {"read", "write", "delete"},
}

# TODO(learner): implement the authorization decision.
#
# Write an `allow if ...` rule that grants access only when the requested
# action (input.action) is one of the actions permitted for the subject's
# role (input.subject.role) in the `permissions` map above.
#
# Hint: use the `in` operator to test membership in permissions[<role>].
# An unknown role should leave the lookup undefined so `allow` stays false.
#
# Until you implement this rule, `allow` is false for every request
# (default-deny), so the three allow-case tests FAIL. Making them pass is the
# Solutions are not published. Iterate until opa test is green.
