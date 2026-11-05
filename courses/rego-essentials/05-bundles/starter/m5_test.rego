package rego_essentials.m5_test

import rego.v1

import data.rego_essentials.m5

staging := {"env": "staging", "allowed_roles": {"read": ["viewer"], "deploy": ["sre"]}}

prod := {"env": "prod", "allowed_roles": {"read": ["viewer"], "deploy": ["sre"]}}

test_developer_allowed_in_staging if {
	m5.allow with input as {"action": "deploy", "user": {"role": "developer"}}
		with data.config as staging
}

test_developer_denied_in_prod if {
	not m5.allow with input as {"action": "deploy", "user": {"role": "developer"}}
		with data.config as prod
}

test_sre_can_deploy_prod if {
	m5.allow with input as {"action": "deploy", "user": {"role": "sre"}}
		with data.config as prod
}

test_missing_config_denied if {
	not m5.allow with input as {"action": "deploy", "user": {"role": "sre"}}
		with data.config as {}
}

test_developer_denied_in_unlisted_env if {
	not m5.allow with input as {"action": "deploy", "user": {"role": "developer"}}
		with data.config as {"env": "prod2", "allowed_roles": {}}
}
