package system.log

# OPA and Enterprise OPA evaluate a rule at data.system.log.mask over every
# decision-log event before it is shipped. The event is the `input` to this
# policy, so the original decision input is at `input.input`. Each string this
# rule returns is a JSON pointer that OPA REMOVES from the logged event, so
# sensitive fields never leave the node in the decision log.
#
# This is the open-source OPA decision-log masking mechanism. Enterprise OPA
# exposes the same idea through its decision_logs.mask configuration, which adds
# richer masking (for example upsert-based redaction) in the log pipeline.
#
# Here we strip two sensitive identifiers from the event: the subject SSN and
# the resource MRN. The care_team and the decision result are left intact,
# because those are exactly what an auditor needs to see.

mask contains "/input/subject/ssn" if {
	input.input.subject.ssn
}

mask contains "/input/resource/mrn" if {
	input.input.resource.mrn
}
