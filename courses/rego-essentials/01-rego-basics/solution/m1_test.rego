package rego_essentials.m1_test

import rego.v1

import data.rego_essentials.m1

test_admin_role if {
	m1.is_admin with input as {"user": {"name": "ana", "roles": ["admin"]}}
}

test_viewer_is_not_admin if {
	not m1.is_admin with input as {"user": {"name": "bo", "roles": ["viewer"]}}
}

test_teams_from_data if {
	m1.user_teams == {"payments", "search"} with input as {"user": {"name": "ana"}}
		with data.teams as {"ana": ["payments", "search"]}
}

test_unknown_user_has_no_teams if {
	count(m1.user_teams) == 0 with input as {"user": {"name": "eve"}}
		with data.teams as {"ana": ["payments"]}
}
