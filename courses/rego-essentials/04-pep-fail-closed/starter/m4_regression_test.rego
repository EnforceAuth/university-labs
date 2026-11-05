package rego_essentials.m4_regression_test

# REGO Rev 3 probes (2026-11-05): equal-but-invalid IDs must deny.
# The first six fail against Rev 4 m4.rego; the last two already pass there.

import rego.v1

import data.rego_essentials.m4

read(id, owner) := {"action": "read", "user": {"id": id}, "resource": {"owner": owner}}

test_null_ids_denied if {
	not m4.allow with input as read(null, null)
}

test_false_ids_denied if {
	not m4.allow with input as read(false, false)
}

test_number_ids_denied if {
	not m4.allow with input as read(42, 42)
}

test_object_ids_denied if {
	not m4.allow with input as read({}, {})
}

test_array_ids_denied if {
	not m4.allow with input as read([], [])
}

test_empty_string_ids_denied if {
	not m4.allow with input as read("", "")
}

test_failed_owner_lookup_denied if {
	not m4.allow with input as {"action": "read", "user": {"id": "u1"}, "resource": {}}
}

test_mismatched_valid_ids_denied if {
	not m4.allow with input as read("u1", "u2")
}
