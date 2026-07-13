package university.migration.parity_test

import data.university.migration.parity

# Parity suite.
#
# Each test encodes a "golden" decision captured from the source system (Styra
# DAS / OPA on OpenShift) BEFORE migration. The migrated policy must return the
# exact same allow or deny for every one of these inputs. If a decision flips,
# the migration changed behavior and the suite fails. That is the whole point of
# parity: prove the move preserved decisions, then cut over with confidence.
#
# Allow parity cases (source system allowed -> migrated must allow).

test_parity_admin_full_access_in_tenant if {
	parity.allow with input as {
		"subject": {"id": "u-admin", "role": "admin", "tenant": "acme"},
		"action": "delete",
		"resource": {"owner": "u-other", "tenant": "acme", "classification": "confidential"},
	}
}

test_parity_editor_may_write_in_tenant if {
	parity.allow with input as {
		"subject": {"id": "u-ed", "role": "editor", "tenant": "acme"},
		"action": "write",
		"resource": {"owner": "u-ed", "tenant": "acme", "classification": "internal"},
	}
}

test_parity_member_may_read_public if {
	parity.allow with input as {
		"subject": {"id": "u-mem", "role": "member", "tenant": "acme"},
		"action": "read",
		"resource": {"owner": "u-ed", "tenant": "acme", "classification": "public"},
	}
}

test_parity_owner_may_delete_own if {
	parity.allow with input as {
		"subject": {"id": "u-mem", "role": "member", "tenant": "acme"},
		"action": "delete",
		"resource": {"owner": "u-mem", "tenant": "acme", "classification": "internal"},
	}
}

# Deny parity cases (source system denied -> migrated must deny). These are the
# regression guards: if the migration accidentally widened access, one of these
# flips to allow and fails.

test_parity_cross_tenant_admin_denied if {
	not parity.allow with input as {
		"subject": {"id": "u-admin", "role": "admin", "tenant": "acme"},
		"action": "read",
		"resource": {"owner": "u-x", "tenant": "globex", "classification": "public"},
	}
}

test_parity_editor_cannot_delete if {
	not parity.allow with input as {
		"subject": {"id": "u-ed", "role": "editor", "tenant": "acme"},
		"action": "delete",
		"resource": {"owner": "u-other", "tenant": "acme", "classification": "internal"},
	}
}

test_parity_member_cannot_read_confidential if {
	not parity.allow with input as {
		"subject": {"id": "u-mem", "role": "member", "tenant": "acme"},
		"action": "read",
		"resource": {"owner": "u-ed", "tenant": "acme", "classification": "confidential"},
	}
}

test_parity_non_owner_cannot_delete if {
	not parity.allow with input as {
		"subject": {"id": "u-mem", "role": "member", "tenant": "acme"},
		"action": "delete",
		"resource": {"owner": "u-other", "tenant": "acme", "classification": "internal"},
	}
}
