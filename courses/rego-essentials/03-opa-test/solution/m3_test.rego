package rego_essentials.m2_test

import rego.v1

import data.rego_essentials.m2

test_viewer_can_read if {
	m2.allow with input as {"action": "read", "user": {"role": "viewer"}}
}

test_editor_can_write if {
	m2.allow with input as {"action": "write", "user": {"role": "editor"}}
}

test_viewer_cannot_write if {
	not m2.allow with input as {"action": "write", "user": {"role": "viewer"}}
}

test_unknown_action_denied if {
	not m2.allow with input as {"action": "delete", "user": {"role": "editor"}}
}

test_empty_input_denied if {
	not m2.allow with input as {}
}
