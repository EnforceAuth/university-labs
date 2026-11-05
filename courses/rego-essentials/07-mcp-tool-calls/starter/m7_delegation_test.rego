package rego_essentials.m7_delegation_test

import rego.v1

import data.rego_essentials.m7_delegation

now := 1762300000000000000 # fixed clock for tests (Nov 2025)

active := {"agent": "agent-7", "user": "user-42", "tools": ["issue_refund"], "status": "active", "expires_at_ns": now + 3600000000000}

call(agent, user, tool, amount) := {
	"agent": {"id": agent, "on_behalf_of": user, "scopes": ["payments:write"]},
	"tool": {"name": tool, "arguments": {"amount": amount}},
}

ok_call := call("agent-7", "user-42", "issue_refund", 40)

test_active_grant_allowed if {
	m7_delegation.delegation_ok with input as ok_call with data.delegation_grants as [active] with time.now_ns as now
}

test_invented_user_denied if {
	not m7_delegation.delegation_ok with input as call("agent-7", "invented-user", "issue_refund", 40)
		with data.delegation_grants as [active] with time.now_ns as now
}

test_other_agent_denied if {
	not m7_delegation.delegation_ok with input as call("agent-9", "user-42", "issue_refund", 40)
		with data.delegation_grants as [active] with time.now_ns as now
}

test_ungranted_tool_denied if {
	not m7_delegation.delegation_ok with input as call("agent-7", "user-42", "delete_database", 40)
		with data.delegation_grants as [active] with time.now_ns as now
}

test_no_grant_data_denied if {
	not m7_delegation.delegation_ok with input as ok_call with time.now_ns as now
}

test_expired_grant_denied if {
	not m7_delegation.delegation_ok with input as ok_call
		with data.delegation_grants as [object.union(active, {"expires_at_ns": now - 1})]
		with time.now_ns as now
}

test_revoked_grant_denied if {
	not m7_delegation.delegation_ok with input as ok_call
		with data.delegation_grants as [object.union(active, {"status": "revoked"})]
		with time.now_ns as now
}

test_missing_expiry_denied if {
	not m7_delegation.delegation_ok with input as ok_call
		with data.delegation_grants as [object.remove(active, ["expires_at_ns"])]
		with time.now_ns as now
}

test_type_mismatch_delegate_denied if {
	not m7_delegation.delegation_ok with input as call("agent-7", 42, "issue_refund", 40)
		with data.delegation_grants as [object.union(active, {"user": 42})]
		with time.now_ns as now
}

test_input_injected_grant_denied if {
	not m7_delegation.delegation_ok with input as object.union(ok_call, {"data": {"delegation_grants": [active]}})
		with time.now_ns as now
}

# Combined enforcement: both decisions must be true.
test_refund_and_delegation_allowed if {
	m7_delegation.refund_allowed with input as ok_call with data.delegation_grants as [active] with time.now_ns as now
}

test_refund_ok_but_delegation_fails_denied if {
	not m7_delegation.refund_allowed with input as call("agent-7", "invented-user", "issue_refund", 40)
		with data.delegation_grants as [active] with time.now_ns as now
}

test_delegation_ok_but_refund_fails_denied if {
	not m7_delegation.refund_allowed with input as call("agent-7", "user-42", "issue_refund", 5000)
		with data.delegation_grants as [active] with time.now_ns as now
}

test_refund_ok_but_grant_expired_denied if {
	not m7_delegation.refund_allowed with input as ok_call
		with data.delegation_grants as [object.union(active, {"expires_at_ns": now - 1})]
		with time.now_ns as now
}
