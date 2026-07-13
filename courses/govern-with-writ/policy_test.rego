package university.writ.docs_authz_test

import data.university.writ.docs_authz

# Allow cases.

test_admin_can_delete_any_org if {
	docs_authz.allow with input as {
		"subject": {"role": "admin", "org": "security"},
		"action": "delete",
		"resource": {"kind": "document", "org": "acme"},
	}
}

test_editor_can_write_own_org if {
	docs_authz.allow with input as {
		"subject": {"role": "editor", "org": "acme"},
		"action": "write",
		"resource": {"kind": "document", "org": "acme"},
	}
}

test_viewer_can_read_own_org if {
	docs_authz.allow with input as {
		"subject": {"role": "viewer", "org": "acme"},
		"action": "read",
		"resource": {"kind": "document", "org": "acme"},
	}
}

# Deny cases (the ones that catch a false allow).

test_editor_cannot_write_other_org if {
	not docs_authz.allow with input as {
		"subject": {"role": "editor", "org": "acme"},
		"action": "write",
		"resource": {"kind": "document", "org": "globex"},
	}
}

test_viewer_cannot_write_own_org if {
	not docs_authz.allow with input as {
		"subject": {"role": "viewer", "org": "acme"},
		"action": "write",
		"resource": {"kind": "document", "org": "acme"},
	}
}

test_unknown_role_cannot_read if {
	not docs_authz.allow with input as {
		"subject": {"role": "guest", "org": "acme"},
		"action": "read",
		"resource": {"kind": "document", "org": "acme"},
	}
}
