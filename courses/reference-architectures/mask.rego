package system.log

# OPA and Enterprise OPA evaluate a rule at data.system.log.mask over every
# decision-log event before it is shipped. The event is the `input` to this
# policy, so the original decision input sits at `input.input`. Each string this
# rule returns is a JSON pointer that OPA REMOVES from the logged event, so the
# sensitive field never leaves the node in the decision log.
#
# This is the open-source OPA decision-log masking mechanism. Enterprise OPA
# exposes the same idea through its decision_logs.mask configuration as a managed
# pipeline stage. Either way, the pointer masked here is the SAME pointer the
# policy names in its redaction obligation (mcp-gateway-authz-v1), so the policy
# and the audit layer agree on exactly which field is sensitive.

mask contains "/input/context/api_token" if {
	input.input.context.api_token
}
