package university.zift.authz_test

import data.university.zift.authz

# Allow cases.

test_admin_can_delete if {
	authz.allow with input as {"subject": {"role": "admin", "id": "u-admin"}, "action": "delete", "resource": {"kind": "doc", "owner_id": "u-other"}}
}

test_editor_can_write_any_doc if {
	authz.allow with input as {"subject": {"role": "editor", "id": "u-ed"}, "action": "write", "resource": {"kind": "doc", "owner_id": "u-other"}}
}

test_viewer_can_read if {
	authz.allow with input as {"subject": {"role": "viewer", "id": "u-vi"}, "action": "read", "resource": {"kind": "doc", "owner_id": "u-other"}}
}

test_owner_can_write_own_doc if {
	# Viewer role, but owns the resource, so the ownership path grants write.
	authz.allow with input as {"subject": {"role": "viewer", "id": "u-vi"}, "action": "write", "resource": {"kind": "doc", "owner_id": "u-vi"}}
}

# Deny cases (the ones that catch a false allow).

test_viewer_cannot_write_others_doc if {
	not authz.allow with input as {"subject": {"role": "viewer", "id": "u-vi"}, "action": "write", "resource": {"kind": "doc", "owner_id": "u-other"}}
}

test_editor_cannot_delete if {
	not authz.allow with input as {"subject": {"role": "editor", "id": "u-ed"}, "action": "delete", "resource": {"kind": "doc", "owner_id": "u-ed"}}
}

test_owner_cannot_delete_own_doc if {
	# Ownership grants read/write only; delete stays role-gated.
	not authz.allow with input as {"subject": {"role": "viewer", "id": "u-vi"}, "action": "delete", "resource": {"kind": "doc", "owner_id": "u-vi"}}
}

test_unknown_role_denied if {
	not authz.allow with input as {"subject": {"role": "guest", "id": "u-g"}, "action": "read", "resource": {"kind": "doc", "owner_id": "u-other"}}
}
