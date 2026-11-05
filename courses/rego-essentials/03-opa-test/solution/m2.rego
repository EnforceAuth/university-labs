package rego_essentials.m2

import rego.v1

default allow := false

allow if {
	input.action == "read"
	input.user.role in {"viewer", "editor"}
}

allow if {
	input.action == "write"
	input.user.role == "editor"
}
