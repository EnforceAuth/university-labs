package rego_essentials.m5

import rego.v1

default allow := false

allow if {
	input.user.role in data.config.allowed_roles[input.action]
}

allow if {
	data.config.env != "prod"
	input.user.role == "developer"
}
