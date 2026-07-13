package university.foundations.authz_test

import data.university.foundations.authz

# Allow cases.

test_admin_can_delete if {
	authz.allow with input as {
		"subject": {"role": "admin", "department": "security"},
		"action": "delete",
		"resource": {"kind": "policy", "owner": "platform"},
	}
}

test_owner_department_can_delete if {
	authz.allow with input as {
		"subject": {"role": "member", "department": "platform"},
		"action": "delete",
		"resource": {"kind": "policy", "owner": "platform"},
	}
}

test_member_can_read if {
	authz.allow with input as {
		"subject": {"role": "member", "department": "finance"},
		"action": "read",
		"resource": {"kind": "report", "owner": "finance"},
	}
}

# Deny cases (the ones that catch a false allow).

test_member_cannot_delete_other_department if {
	not authz.allow with input as {
		"subject": {"role": "member", "department": "finance"},
		"action": "delete",
		"resource": {"kind": "policy", "owner": "platform"},
	}
}

test_member_cannot_write if {
	not authz.allow with input as {
		"subject": {"role": "member", "department": "finance"},
		"action": "write",
		"resource": {"kind": "report", "owner": "finance"},
	}
}

test_unknown_role_cannot_read if {
	not authz.allow with input as {
		"subject": {"role": "guest", "department": "finance"},
		"action": "read",
		"resource": {"kind": "report", "owner": "finance"},
	}
}
