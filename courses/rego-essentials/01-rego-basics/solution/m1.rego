package rego_essentials.m1

import rego.v1

is_admin if "admin" in input.user.roles

user_teams contains team if {
	some team in data.teams[input.user.name]
}
