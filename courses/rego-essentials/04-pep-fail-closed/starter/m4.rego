package rego_essentials.m4

import rego.v1

default allow := false

allow if {
	input.action == "read"
	input.resource.owner == input.user.id
}
