package rego_essentials.m7_delegation

# Separate active-grant example (Rev 6). Grants are TRUSTED data loaded by your
# systems, never taken from the agent's input. Schema per grant:
#   {"agent": "agent-7", "user": "user-42", "tools": ["issue_refund"],
#    "status": "active", "expires_at_ns": 1893456000000000000}
# This checks grant membership and lifecycle (status + expiry vs time.now_ns).
# It does not prove the trusted loader's records are genuine.

import rego.v1

import data.rego_essentials.m7

default delegation_ok := false

delegation_ok if {
	some grant in data.delegation_grants
	grant.status == "active"
	is_number(grant.expires_at_ns)
	time.now_ns() < grant.expires_at_ns
	is_string(input.agent.id)
	is_string(input.agent.on_behalf_of)
	grant.agent == input.agent.id
	grant.user == input.agent.on_behalf_of
	input.tool.name in grant.tools
}

# A refund that needs delegation requires BOTH decisions on the same input.
default refund_allowed := false

refund_allowed if {
	input.tool.name == "issue_refund"
	m7.allow
	delegation_ok
}
