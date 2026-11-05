package rego_essentials.m7

import rego.v1

default allow := false

read_only_tools := {"search_docs", "get_ticket"}

allow if {
	input.tool.name in read_only_tools
	is_array(input.agent.scopes)
	"tickets:read" in input.agent.scopes
}

allow if {
	input.tool.name == "issue_refund"
	is_array(input.agent.scopes)
	"payments:write" in input.agent.scopes
	is_number(input.tool.arguments.amount)
	input.tool.arguments.amount >= 0
	input.tool.arguments.amount <= 100
	is_string(input.agent.on_behalf_of)
	input.agent.on_behalf_of != ""
}

reasons contains "refund over limit" if {
	input.tool.name == "issue_refund"
	is_number(input.tool.arguments.amount)
	input.tool.arguments.amount > 100
}

reasons contains "invalid refund amount" if {
	input.tool.name == "issue_refund"
	not valid_amount
}

reasons contains "invalid delegation" if {
	input.tool.name == "issue_refund"
	not valid_delegate
}

reasons contains "missing scope" if {
	not allow
	not has_required_scope
}

valid_amount if {
	is_number(input.tool.arguments.amount)
	input.tool.arguments.amount >= 0
}

valid_delegate if {
	is_string(input.agent.on_behalf_of)
	input.agent.on_behalf_of != ""
}

required_scope := "tickets:read" if input.tool.name in read_only_tools

required_scope := "payments:write" if input.tool.name == "issue_refund"

has_required_scope if {
	is_array(input.agent.scopes)
	required_scope in input.agent.scopes
}
