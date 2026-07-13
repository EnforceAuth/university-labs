package university.opa_eopa.fundamentals

# Vendor-neutral service-to-service authorization for the OPA & Enterprise OPA
# Fundamentals lab. This is standard OPA/Rego v1: default-deny, data-driven,
# with a helper rule and a comprehension. Enterprise OPA (the `eopa` binary)
# evaluates this exact policy the same way; the enterprise features
# (decision-log masking, delta bundles, live datasources) sit around the
# policy, not inside it. EnforceAuth's Writ control plane governs and deploys
# policies like this; it is not on the request path.
#
# STARTER: the scaffolding (data, helpers, method sets) is provided. The two
# decision rules are stubbed out with a TODO. Implement them until
# Keep iterating until `opa test` is green.

default allow := false

# Data-driven allow list: which service accounts may call which API tier.
# In production this ships as bundle data (data.json) rather than being written
# in the policy; it is inlined here so the lab is self-contained and
# `opa test` needs no extra data file.
account_tiers := {
	"svc-checkout": "write",
	"svc-billing": "write",
	"svc-reporting": "read",
	"svc-audit": "read",
}

read_methods := {"GET", "HEAD"}

write_methods := {"POST", "PUT", "DELETE"}

# Helper rule: the tier granted to the calling account. If the account is not
# on the allow list the lookup is undefined, so every rule that depends on it
# fails and `allow` stays at its default of false.
subject_tier := account_tiers[input.subject.account]

# Helper built with a comprehension: the set of accounts whose tier is "write".
# Comprehensions build a new collection by iterating existing data, so the
# write list stays in sync with account_tiers automatically.
write_accounts := {account | some account, tier in account_tiers; tier == "write"}

# TODO(learner): implement the two allow rules using the scaffolding above.
#
# Rule 1 - a read-tier OR write-tier account may call a read method:
#     allow if {
#         subject_tier in {"read", "write"}
#         input.method in read_methods
#     }
#
# Rule 2 - only a write-tier account may call a write method:
#     allow if {
#         input.subject.account in write_accounts
#         input.method in write_methods
#     }
#
# Remember: multiple `allow if` rules are a logical OR, so add both as separate
# rules. Delete this stub once you have written them. Until then `allow` is
# always the default `false`, so every allow test fails while the deny tests
# already pass - that is the RED starting state you are fixing.
