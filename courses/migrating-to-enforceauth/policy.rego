package university.migration.parity

# A teaching policy for the "Migrating to EnforceAuth" course.
#
# This is the SAME Rego that ran on the source system (Styra DAS or OPA on
# OpenShift). Migration preserves it as-is: no rewrite. What changes is where the
# policy lives (Git), how it is delivered (Writ signs it into a bundle and
# promotes dev -> staging -> prod, deploy-action ships it via the EnforceAuth
# API), and how it is audited. The decision logic does not change, which is what
# lets a parity suite prove behavior is preserved.
#
# The PDP that evaluates this is still OPA or Enterprise OPA. Writ is the control
# plane over those PDPs; it is not a PDP on the request path.
#
# Input shape:
#   {
#     "subject":  {"id": "...", "role": "admin"|"editor"|"member", "tenant": "..."},
#     "action":   "read" | "write" | "delete",
#     "resource": {"owner": "<subject id>", "tenant": "...", "classification": "public"|"internal"|"confidential"}
#   }
#
# Rules preserved from the source system:
#   - Tenant isolation: a subject can only act within its own tenant.
#   - Admins have full access within their tenant.
#   - Editors may read and write within their tenant.
#   - Anyone in the tenant may read a public resource.
#   - Owners may delete a resource they own.
# Everything else falls through to the default deny.

default allow := false

# Tenant isolation gate: every allow path requires the subject and resource to
# share a tenant. Cross-tenant access is always denied. This scaffolding is
# provided; your allow rules must build on it.
same_tenant if input.subject.tenant == input.resource.tenant

# TODO(learner): Reconstruct the four preserved allow paths so the parity suite
# passes. The policy currently has no allow rule beyond the default deny, so
# every allow parity test fails. Preserve the source-system behavior exactly:
#
#   1. Admins have full access within their own tenant.
#   2. Editors may read and write within their tenant (not delete).
#   3. Anyone in the tenant may read a resource classified "public".
#   4. Owners may delete a resource they own.
#
# Write each as its own `allow if { ... }` rule (multiple rules with the same
# name are OR-ed together). Every rule must include `same_tenant` so tenant
# isolation still holds. Use the `in` operator for the editor action set.
# Run `opa test courses/migrating-to-enforceauth -v`
# until `opa test` reports PASS: 8/8.
