package rego_essentials.m4

import rego.v1

default allow := false

allow if {
	input.action == "read"
	is_string(input.user.id)
	input.user.id != ""
	is_string(input.resource.owner)
	input.resource.owner != ""
	input.resource.owner == input.user.id
}
