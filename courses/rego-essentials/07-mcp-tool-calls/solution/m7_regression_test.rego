package rego_essentials.m7_regression_test

# Regressions for Check QA probes (2026-11-05). Nine fail against Rev 2 m7.rego; string-amount and object-scopes denials already pass there.

import rego.v1

import data.rego_essentials.m7

refund(amount, delegate, scopes) := {
	"agent": {"scopes": scopes, "on_behalf_of": delegate},
	"tool": {"name": "issue_refund", "arguments": {"amount": amount}},
}

ok_scopes := ["payments:write"]

test_null_amount_denied if {
	not m7.allow with input as refund(null, "user-42", ok_scopes)
}

test_false_amount_denied if {
	not m7.allow with input as refund(false, "user-42", ok_scopes)
}

test_negative_amount_denied if {
	not m7.allow with input as refund(-1, "user-42", ok_scopes)
}

test_string_amount_denied if {
	not m7.allow with input as refund("40", "user-42", ok_scopes)
}

test_null_delegate_denied if {
	not m7.allow with input as refund(40, null, ok_scopes)
}

test_false_delegate_denied if {
	not m7.allow with input as refund(40, false, ok_scopes)
}

test_numeric_delegate_denied if {
	not m7.allow with input as refund(40, 42, ok_scopes)
}

test_object_delegate_denied if {
	not m7.allow with input as refund(40, {}, ok_scopes)
}

test_object_scopes_denied if {
	not m7.allow with input as {
		"agent": {"scopes": {"tickets:read": true}, "on_behalf_of": "user-42"},
		"tool": {"name": "get_ticket", "arguments": {}},
	}
}

test_missing_read_scope_has_reason if {
	"missing scope" in m7.reasons with input as {
		"agent": {"scopes": [], "on_behalf_of": "user-42"},
		"tool": {"name": "get_ticket", "arguments": {}},
	}
}

test_invalid_amount_reason if {
	"invalid refund amount" in m7.reasons with input as refund(null, "user-42", ok_scopes)
}
