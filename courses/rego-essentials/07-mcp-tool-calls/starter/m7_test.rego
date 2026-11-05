package rego_essentials.m7_test

import rego.v1

import data.rego_essentials.m7

agent := {"scopes": ["tickets:read", "payments:write"], "on_behalf_of": "user-42"}

test_read_tool_allowed if {
	m7.allow with input as {"agent": agent, "tool": {"name": "get_ticket", "arguments": {}}}
}

test_small_refund_allowed if {
	m7.allow with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {"amount": 40}}}
}

test_large_refund_denied if {
	not m7.allow with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {"amount": 5000}}}
	"refund over limit" in m7.reasons with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {"amount": 5000}}}
}

test_refund_without_user_denied if {
	not m7.allow with input as {
		"agent": {"scopes": ["payments:write"], "on_behalf_of": ""},
		"tool": {"name": "issue_refund", "arguments": {"amount": 40}},
	}
}

test_unknown_tool_denied if {
	not m7.allow with input as {"agent": agent, "tool": {"name": "delete_database", "arguments": {}}}
}

test_missing_scope_reason if {
	"missing scope" in m7.reasons with input as {
		"agent": {"scopes": [], "on_behalf_of": "user-42"},
		"tool": {"name": "issue_refund", "arguments": {"amount": 40}},
	}
}

test_refund_at_limit_allowed if {
	m7.allow with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {"amount": 100}}}
}

test_refund_just_over_limit_denied if {
	not m7.allow with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {"amount": 101}}}
}

test_refund_missing_amount_denied if {
	not m7.allow with input as {"agent": agent, "tool": {"name": "issue_refund", "arguments": {}}}
}
