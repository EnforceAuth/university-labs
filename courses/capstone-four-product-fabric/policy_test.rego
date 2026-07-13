package university.capstone.authz_test

import data.system.log as declog
import data.university.capstone.authz

# --- Allow cases (one per rule the fabric enforces). ---

# Role + tenancy: an active editor exporting an internal record in their own org.
test_role_grant_editor_export_own_org if {
	authz.allow with input as editor_export_request
	authz.decision.allow == true with input as editor_export_request
}

# Ownership: an active viewer reading a record they own, even in another org.
test_owner_can_read_owned_record_cross_org if {
	authz.allow with input as owner_read_request
}

# Restricted: an active admin reading a restricted record with an approved
# change ticket (the ITSM signal Herald federates).
test_restricted_allowed_with_approval if {
	authz.allow with input as restricted_approved_request
}

# --- Deny cases (the ones that catch a false allow). ---

# Same role and action, wrong org: an editor cannot write across orgs.
test_editor_cannot_write_other_org if {
	not authz.allow with input as {
		"subject": {"id": "u1", "role": "editor", "org": "acme", "employment_status": "active", "ssn": "111-22-3333"},
		"action": "write",
		"resource": {"kind": "record", "org": "globex", "owner_id": "u9", "classification": "internal", "card_number": "4111111111111111"},
		"context": {"change_ticket": {"status": "none"}},
	}
}

# A terminated employee is denied even with a permitted role and their own org.
test_terminated_employee_denied if {
	not authz.allow with input as {
		"subject": {"id": "u2", "role": "admin", "org": "acme", "employment_status": "terminated", "ssn": "222-33-4444"},
		"action": "read",
		"resource": {"kind": "record", "org": "acme", "owner_id": "u9", "classification": "internal", "card_number": "4111111111111111"},
		"context": {"change_ticket": {"status": "approved"}},
	}
}

# Restricted record without an approved change ticket: the missing ITSM signal denies.
test_restricted_denied_without_approval if {
	not authz.allow with input as {
		"subject": {"id": "u3", "role": "admin", "org": "acme", "employment_status": "active", "ssn": "333-44-5555"},
		"action": "read",
		"resource": {"kind": "record", "org": "acme", "owner_id": "u9", "classification": "restricted", "card_number": "4111111111111111"},
		"context": {"change_ticket": {"status": "pending"}},
	}
}

# Least privilege: a viewer cannot delete, even in their own org. Delete is
# role-gated and not owner-grantable.
test_viewer_cannot_delete if {
	not authz.allow with input as {
		"subject": {"id": "u4", "role": "viewer", "org": "acme", "employment_status": "active", "ssn": "444-55-6666"},
		"action": "delete",
		"resource": {"kind": "record", "org": "acme", "owner_id": "u4", "classification": "internal", "card_number": "4111111111111111"},
		"context": {"change_ticket": {"status": "approved"}},
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
test_mask_selects_ssn_and_card if {
	"/input/subject/ssn" in mask_paths
	"/input/resource/card_number" in mask_paths
}

# Set-level: the mask does not select the org, the classification, or the result.
test_mask_does_not_select_org_or_result if {
	not "/input/resource/org" in mask_paths
	not "/input/resource/classification" in mask_paths
	not "/result" in mask_paths
}

# Behavior-level: after masking, the SSN and card number are actually gone from
# the shipped event. This is the redaction the objective promises.
test_mask_redacts_ssn_and_card_from_event if {
	not redacted_event.input.subject.ssn
	not redacted_event.input.resource.card_number
}

# Behavior-level: masking preserves the evidence an auditor and a Writ replay
# need. The org, the classification, and the decision result survive intact.
test_mask_preserves_evidence_after_redaction if {
	redacted_event.input.resource.org == "acme"
	redacted_event.input.resource.classification == "internal"
	redacted_event.result.allow == true
}

# --- Fixtures. ---

editor_export_request := {
	"subject": {"id": "u1", "role": "editor", "org": "acme", "employment_status": "active", "ssn": "111-22-3333"},
	"action": "export",
	"resource": {"kind": "record", "org": "acme", "owner_id": "u9", "classification": "internal", "card_number": "4111111111111111"},
	"context": {"change_ticket": {"status": "none"}},
}

owner_read_request := {
	"subject": {"id": "u7", "role": "viewer", "org": "acme", "employment_status": "active", "ssn": "777-88-9999"},
	"action": "read",
	"resource": {"kind": "record", "org": "globex", "owner_id": "u7", "classification": "internal", "card_number": "4111111111111111"},
	"context": {"change_ticket": {"status": "none"}},
}

restricted_approved_request := {
	"subject": {"id": "u5", "role": "admin", "org": "acme", "employment_status": "active", "ssn": "555-66-7777"},
	"action": "read",
	"resource": {"kind": "record", "org": "acme", "owner_id": "u9", "classification": "restricted", "card_number": "4111111111111111"},
	"context": {"change_ticket": {"status": "approved"}},
}

# A decision-log event as OPA hands it to the mask policy: the original decision
# input sits under /input, the outcome under /result.
log_event := {
	"input": editor_export_request,
	"result": {"allow": true, "policy_id": "customer-records-v1"},
}
