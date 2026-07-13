package system.log

# Decision-log masking for the capstone policy. OPA and Enterprise OPA evaluate
# a rule at data.system.log.mask over every decision-log event before it is
# shipped. The event is the `input` to THIS policy, so the original decision
# input sits at `input.input`. Each string this rule returns is a JSON pointer
# that OPA REMOVES from the logged event, so the sensitive fields never leave
# the node in the decision log.
#
# This is the open-source OPA decision-log masking mechanism. Enterprise OPA
# exposes the same idea through its decision_logs.mask configuration (a managed
# pipeline stage with richer redaction, for example upsert-based masking).
#
# Here we strip the two sensitive identifiers that the customer-records request
# carries: the subject SSN and the resource card number. The org, the
# classification, and the decision result are left intact, because those are
# exactly the evidence an auditor and a Writ replay need.

mask contains "/input/subject/ssn" if {
	input.input.subject.ssn
}

mask contains "/input/resource/card_number" if {
	input.input.resource.card_number
}
