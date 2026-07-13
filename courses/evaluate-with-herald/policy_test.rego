package university.herald.authz_test

import data.university.herald.authz

# Allow cases.

test_active_analyst_can_query_internal if {
	authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "active"},
		"action": "query",
		"resource": {"dataset": "orders", "classification": "internal"},
		"context": {"change_ticket": {"status": "none"}, "risk": {"level": "low"}},
	}
}

test_data_platform_can_read_public if {
	authz.allow with input as {
		"subject": {"idp_groups": ["data-platform"], "employment_status": "active"},
		"action": "read",
		"resource": {"dataset": "docs", "classification": "public"},
		"context": {"change_ticket": {"status": "none"}, "risk": {"level": "low"}},
	}
}

test_restricted_query_with_approval_and_low_risk if {
	authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "active"},
		"action": "query",
		"resource": {"dataset": "revenue", "classification": "restricted"},
		"context": {"change_ticket": {"status": "approved"}, "risk": {"level": "low"}},
	}
}

# Deny cases (the ones that catch a false allow).

# HRIS: a terminated employee is denied despite a valid group.
test_terminated_employee_denied if {
	not authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "terminated"},
		"action": "query",
		"resource": {"dataset": "orders", "classification": "internal"},
		"context": {"change_ticket": {"status": "none"}, "risk": {"level": "low"}},
	}
}

# SIEM: a high risk signal denies an otherwise-allowable restricted query.
test_restricted_denied_on_high_risk if {
	not authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "active"},
		"action": "query",
		"resource": {"dataset": "revenue", "classification": "restricted"},
		"context": {"change_ticket": {"status": "approved"}, "risk": {"level": "high"}},
	}
}

# ITSM: a missing approval denies a restricted query.
test_restricted_denied_without_approved_ticket if {
	not authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "active"},
		"action": "query",
		"resource": {"dataset": "revenue", "classification": "restricted"},
		"context": {"change_ticket": {"status": "pending"}, "risk": {"level": "low"}},
	}
}

# Read-only scope (the model this course adopts): a mutating action is denied
# even for a legitimate active, authorized subject. This is the policy-level
# echo of that modeled scope.
test_write_action_denied_read_only_scope if {
	not authz.allow with input as {
		"subject": {"idp_groups": ["analysts"], "employment_status": "active"},
		"action": "write",
		"resource": {"dataset": "orders", "classification": "internal"},
		"context": {"change_ticket": {"status": "approved"}, "risk": {"level": "low"}},
	}
}

# IdP: a subject in no authorized group is denied.
test_unauthorized_group_denied if {
	not authz.allow with input as {
		"subject": {"idp_groups": ["contractors"], "employment_status": "active"},
		"action": "query",
		"resource": {"dataset": "orders", "classification": "internal"},
		"context": {"change_ticket": {"status": "none"}, "risk": {"level": "low"}},
	}
}
