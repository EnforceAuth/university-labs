package rego_essentials.m7

import rego.v1

default allow := false

read_only_tools := {"search_docs", "get_ticket"}

allow if {
	input.tool.name in read_only_tools
	"tickets:read" in input.agent.scopes
}

allow if {
	input.tool.name == "issue_refund"
	"payments:write" in input.agent.scopes
	input.tool.arguments.amount <= 100
	input.agent.on_behalf_of != ""
}

reasons contains "refund over limit" if {
	input.tool.name == "issue_refund"
	input.tool.arguments.amount > 100
}

reasons contains "missing scope" if {
	not allow
	not input.tool.name in read_only_tools
	not "payments:write" in input.agent.scopes
}
