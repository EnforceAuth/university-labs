package university.gettingstarted.writ

# A first governed policy for the "Getting Started with the EnforceAuth Control
# Plane" course. It models the decision a Policy Decision Point (PDP) such as OPA
# or Enterprise OPA returns for a single request, scoped to the full Writ entity
# hierarchy (tenant -> org -> system -> app). This is standard OPA/Rego. Writ, the
# control plane, would sign this policy into a bundle and promote it from dev to
# staging to prod; Writ is not a PDP on the request path.
#
# Input shape (subject and resource each carry all four hierarchy levels):
#   {
#     "subject":  {"role": "...", "tenant": "...", "org": "...", "system": "...", "app": "..."},
#     "action":   "read" | "publish" | "restart" | "delete",
#     "resource": {"kind": "...", "tenant": "...", "org": "...", "system": "...", "app": "..."}
#   }
#
# Isolation is a nested chain, checked before any role. Each level implies the one
# above it, so scope narrows as you descend the hierarchy:
#   - same_tenant: subject.tenant == resource.tenant
#   - same_org:    same_tenant  AND subject.org    == resource.org
#   - same_system: same_org     AND subject.system == resource.system
#   - same_app:    same_system  AND subject.app    == resource.app
#
# The isolation helpers below are written for you. Your job is the four allow
# rules, one per hierarchy level (widest scope to narrowest):
#   - Same-tenant admins may take any action.   (tenant-scoped)
#   - Same-org publishers may publish.          (org-scoped)
#   - Same-system operators may restart.        (system-scoped)
#   - Same-app members may read.                (app-scoped)
# Everything else must fall through to the default deny.

default allow := false

# TODO(learner): implement the four allow rules described above, one per
# hierarchy level. Each rule ORs into `allow` (incremental definition): write a
# separate `allow if { ... }` block per level. Combine the matching isolation
# helper (same_tenant / same_org / same_system / same_app) with the role and, for
# the narrower levels, the action. Delete this stub once your rules exist; while
# it is the only definition, `allow` is always false and every allow test fails.
#
# Example of the shape (not the answer):
#   allow if {
#       same_org
#       input.action == "publish"
#       input.subject.role == "publisher"
#   }
#
# When your rules are correct, `opa test` reports PASS: 8/8. Check your work
# Keep iterating until `opa test` is green.

# Isolation helpers (provided). Do not weaken these: they are the tenant, org,
# system, and app boundaries the deny tests protect.
same_tenant if input.subject.tenant == input.resource.tenant

same_org if {
	same_tenant
	input.subject.org == input.resource.org
}

same_system if {
	same_org
	input.subject.system == input.resource.system
}

same_app if {
	same_system
	input.subject.app == input.resource.app
}
