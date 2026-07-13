package university.reference.authz_test

import data.university.reference.authz

# Allow cases.

test_admin_can_delete if {
	authz.allow with input as {"subject": {"role": "admin"}, "action": "delete", "resource": {"kind": "policy"}}
}

test_editor_can_write if {
	authz.allow with input as {"subject": {"role": "editor"}, "action": "write", "resource": {"kind": "policy"}}
}

test_viewer_can_read if {
	authz.allow with input as {"subject": {"role": "viewer"}, "action": "read", "resource": {"kind": "policy"}}
}

# Deny cases (the ones that catch a false allow).

test_viewer_cannot_write if {
	not authz.allow with input as {"subject": {"role": "viewer"}, "action": "write", "resource": {"kind": "policy"}}
}

test_editor_cannot_delete if {
	not authz.allow with input as {"subject": {"role": "editor"}, "action": "delete", "resource": {"kind": "policy"}}
}

test_unknown_role_denied if {
	not authz.allow with input as {"subject": {"role": "guest"}, "action": "read", "resource": {"kind": "policy"}}
}
