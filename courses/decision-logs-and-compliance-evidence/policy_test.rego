package university.grc.authz_test

import data.system.log as declog
import data.university.grc.authz

# --- Allow cases (structured-decision assertions). ---

test_care_team_member_can_read if {
	authz.allow with input as care_team_request
	authz.decision.reason == "care-team-match" with input as care_team_request
	count(authz.decision.obligations) == 0 with input as care_team_request
}

test_break_glass_allows_with_justification if {
	authz.allow with input as break_glass_request
	authz.decision.reason == "break-glass" with input as break_glass_request
	"notify-privacy-officer" in authz.decision.obligations with input as break_glass_request
}

# --- Deny cases (the ones that catch a false allow). ---

test_non_care_team_clinician_denied if {
	not authz.allow with input as {
		"subject": {"id": "u2", "role": "clinician", "care_teams": ["oncology"], "ssn": "222-33-4444"},
		"action": "read",
		"resource": {"type": "record", "care_team": "cardiology", "mrn": "MRN-88"},
	}
}

test_break_glass_denied_without_justification if {
	not authz.allow with input as {
		"subject": {"id": "u3", "role": "emergency", "care_teams": ["ed"], "ssn": "333-44-5555"},
		"action": "read",
		"resource": {"type": "record", "care_team": "cardiology", "mrn": "MRN-88"},
		"context": {"justification": ""},
	}
}

test_write_action_denied if {
	not authz.allow with input as {
		"subject": {"id": "u1", "role": "clinician", "care_teams": ["cardiology"], "ssn": "123-45-6789"},
		"action": "write",
		"resource": {"type": "record", "care_team": "cardiology", "mrn": "MRN-88"},
	}
}

# --- Masking-aware tests (data.system.log.mask over a decision-log event). ---

# The pointers the mask rule returns for our fixture event.
mask_paths := paths if {
	paths := declog.mask with input as log_event
}

# What OPA actually ships: the event with each masked pointer removed. OPA's
# decision-log plugin performs this removal; here we reproduce it with
# json.remove so the tests assert real redaction, not just the mask set. The
# mask pointers carry a leading "/" (JSON pointer); json.remove takes
# slash-separated paths, so we strip the leading slash.
redacted_event := json.remove(log_event, {trim_left(p, "/") | some p in mask_paths})

# Set-level: the sensitive pointers are selected for masking.
test_mask_selects_ssn_and_mrn if {
	"/input/subject/ssn" in mask_paths
	"/input/resource/mrn" in mask_paths
}

# Set-level: the mask does not select the context or the result.
test_mask_does_not_select_care_team_or_result if {
	not "/input/resource/care_team" in mask_paths
	not "/result" in mask_paths
}

# Behavior-level: after masking, the SSN and MRN are actually gone from the
# shipped event. This is the redaction the objective promises, not just a set
# membership check.
test_mask_redacts_ssn_and_mrn_from_event if {
	not redacted_event.input.subject.ssn
	not redacted_event.input.resource.mrn
}

# Behavior-level: masking preserves the evidence an auditor needs. The care team
# and the decision result survive redaction intact.
test_mask_preserves_care_team_and_result_after_redaction if {
	redacted_event.input.resource.care_team == "cardiology"
	redacted_event.result.allow == true
}

# --- Fixtures. ---

care_team_request := {
	"subject": {"id": "u1", "role": "clinician", "care_teams": ["cardiology"], "ssn": "123-45-6789"},
	"action": "read",
	"resource": {"type": "record", "care_team": "cardiology", "mrn": "MRN-88"},
}

break_glass_request := {
	"subject": {"id": "u9", "role": "emergency", "care_teams": ["ed"], "ssn": "999-88-7777"},
	"action": "read",
	"resource": {"type": "record", "care_team": "cardiology", "mrn": "MRN-88"},
	"context": {"justification": "code-blue, patient unresponsive"},
}

# A decision-log event as OPA hands it to the mask policy: the original decision
# input sits under /input, the outcome under /result.
log_event := {
	"input": care_team_request,
	"result": {"allow": true, "reason": "care-team-match", "obligations": []},
}
