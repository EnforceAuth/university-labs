package rego_essentials.m4_test

import rego.v1

import data.rego_essentials.m4

test_owner_can_read if {
	m4.allow with input as {"action": "read", "user": {"id": "u1"}, "resource": {"owner": "u1"}}
}

test_non_owner_denied if {
	not m4.allow with input as {"action": "read", "user": {"id": "u2"}, "resource": {"owner": "u1"}}
}

test_missing_resource_denied if {
	not m4.allow with input as {"action": "read", "user": {"id": "u1"}}
}
