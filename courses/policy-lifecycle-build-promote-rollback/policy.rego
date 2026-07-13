package university.lifecycle.promotion

# STARTER: this is the exercise. The policy bundle that travels through the
# deploy pipeline for the "Policy Lifecycle: Build, Promote & Roll Back"
# course. It authorizes who may promote or roll back an OPA policy bundle in
# each environment. This is standard OPA/Rego evaluated by a PDP (OPA or
# Enterprise OPA). EnforceAuth's Writ control plane signs this bundle from Git
# and promotes it dev -> staging -> prod; deploy-action performs the deploy
# over GitHub OIDC. Neither Writ nor deploy-action is a PDP on the request path.
#
# Input shape:
#   {
#     "subject": {"role": "..."},                      # engineer | release-manager | admin
#     "action":  "promote" | "rollback",
#     "target":  {"environment": "...", "bundle": "..."},  # dev | staging | prod
#     "change":  {"approved": true|false, "commit_sha": "..."}
#   }
#
# Rules you must implement (each maps to tests in policy_test.rego):
#   - Admins may promote or roll back in any environment.
#   - Engineers and release managers may promote to dev with a pinned commit_sha
#     (an arbitrary role such as "intern" is denied even with a commit_sha).
#   - Release managers may promote to staging with a pinned commit_sha.
#   - Promotion to prod requires a release manager and an approved change.
#   - Rollback in prod requires a release manager and a prior commit_sha.
# Everything else falls through to the default deny.

default allow := false

# TODO(learner): implement the promotion/rollback authorization rules above.
#
# Write one incremental `allow if { ... }` block per rule. In Rego, multiple
# `allow if` rules OR together: a request is allowed if ANY block succeeds, and
# is denied by `default allow := false` above when none do. Use the `in`
# operator to test role membership. For example, the admin rule is:
#
#   allow if {
#       input.subject.role == "admin"
#       input.action in {"promote", "rollback"}
#   }
#
# Add the remaining blocks (dev promote, staging promote, prod promote, prod
# rollback) until every case in policy_test.rego passes:
#
#   opa test courses/policy-lifecycle-build-promote-rollback -v
#
# Keep iterating until `opa test` is green.
#
# Until you implement these rules, the starter denies everything by default, so
# the three allow tests in policy_test.rego fail. That RED state is the exercise.
