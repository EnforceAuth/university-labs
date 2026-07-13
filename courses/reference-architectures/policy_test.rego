package university.prod.authz_test

import data.system.log as declog
import data.university.prod.authz

# --- Allow cases (structured-decision assertions). ---

test_same_domain_standard_allowed if {
	authz.allow with input as standard_request
	authz.decision.reason == "same-domain-standard" with input as standard_request
}

test_privileged_tool_with_approval_allowed if {
	authz.allow with input as privileged_request
	authz.decision.reason == "privileged-tool-approved" with input as privileged_request
}

# --- Deny cases: fail-closed is what catches an over-permissive rule. ---

# A workload from a different trust domain is denied, even with verified mTLS.
test_cross_trust_domain_denied if {
	not authz.allow with input as {
		"subject": {"spiffe_id": "spiffe://staging.enforceauth/agent/x", "trust_domain": "staging.enforceauth"},
		"action": "invoke",
		"resource": {"tool": "notes.read", "classification": "standard", "owner_domain": "prod.enforceauth"},
		"context": {"mtls_verified": true, "api_token": "sk-live-aaa"},
	}
}

# No verified workload mTLS: the fail-closed default denies rather than leaks.
test_missing_mtls_denied if {
	not authz.allow with input as {
		"subject": {"spiffe_id": "spiffe://prod.enforceauth/agent/x", "trust_domain": "prod.enforceauth"},
		"action": "invoke",
		"resource": {"tool": "notes.read", "classification": "standard", "owner_domain": "prod.enforceauth"},
		"context": {"mtls_verified": false, "api_token": "sk-live-bbb"},
	}
}

# A restricted tool without an approval reference is denied.
test_restricted_tool_without_approval_denied if {
	not authz.allow with input as {
		"subject": {"spiffe_id": "spiffe://prod.enforceauth/agent/x", "trust_domain": "prod.enforceauth"},
		"action": "invoke",
		"resource": {"tool": "refund.issue", "classification": "restricted", "owner_domain": "prod.enforceauth"},
		"context": {"mtls_verified": true, "api_token": "sk-live-ccc", "approval_ref": ""},
	}
}

# --- Masking-aware decision tests. ---

# The decision object never carries the caller's secret or any context field.
test_decision_does_not_leak_token if {
	keys := {k | some k, _ in authz.decision} with input as standard_request
	not "api_token" in keys
	not "context" in keys
}

# The policy names the sensitive field the audit layer must redact.
test_policy_flags_token_for_redaction if {
	"redact:/input/context/api_token" in authz.decision.obligations with input as standard_request
}

# --- Decision-log masking tests (data.system.log.mask over an event). ---

mask_paths := paths if {
	paths := declog.mask with input as log_event
}

# What OPA ships: the event with each masked pointer removed. The mask pointers
# carry a leading "/" (JSON pointer); json.remove takes slash-separated paths, so
# strip the leading slash.
redacted_event := json.remove(log_event, {trim_left(p, "/") | some p in mask_paths})

# Set-level: the sensitive pointer is selected for masking.
test_mask_selects_api_token if {
	"/input/context/api_token" in mask_paths
}

# Behavior-level: after masking, the token is actually gone from the shipped event.
test_mask_redacts_token_from_event if {
	not redacted_event.input.context.api_token
}

# Behavior-level: masking preserves the evidence an auditor needs. The identity
# and the decision result survive redaction intact.
test_mask_preserves_decision_fields if {
	redacted_event.input.subject.trust_domain == "prod.enforceauth"
	redacted_event.result.allow == true
}

# The masking-aware check: every field the policy flags for redaction is actually
# removed by the decision-log mask. This closes the loop between what the policy
# calls sensitive and what the audit layer scrubs.
test_every_redaction_obligation_is_masked if {
	obs := authz.decision.obligations with input as standard_request
	pointers := {trim_prefix(o, "redact:") | some o in obs; startswith(o, "redact:")}
	every ptr in pointers {
		ptr in declog.mask with input as log_event
	}
}

# --- Fixtures. ---

standard_request := {
	"subject": {"spiffe_id": "spiffe://prod.enforceauth/agent/support-bot", "trust_domain": "prod.enforceauth", "assurance": "mtls"},
	"action": "invoke",
	"resource": {"tool": "notes.read", "classification": "standard", "owner_domain": "prod.enforceauth"},
	"context": {"mtls_verified": true, "api_token": "sk-live-abc123"},
}

privileged_request := {
	"subject": {"spiffe_id": "spiffe://prod.enforceauth/agent/refund-bot", "trust_domain": "prod.enforceauth", "assurance": "mtls"},
	"action": "invoke",
	"resource": {"tool": "refund.issue", "classification": "restricted", "owner_domain": "prod.enforceauth"},
	"context": {"mtls_verified": true, "api_token": "sk-live-xyz789", "approval_ref": "CHG-4471"},
}

# A decision-log event as OPA hands it to the mask policy: the original decision
# input sits under /input, the outcome under /result.
log_event := {
	"input": standard_request,
	"result": {"allow": true, "reason": "same-domain-standard", "obligations": ["redact:/input/context/api_token"]},
}
