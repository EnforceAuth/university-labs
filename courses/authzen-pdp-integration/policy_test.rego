package university.authzen.evaluation_test

import data.university.authzen.evaluation

# Allow cases.

test_admin_can_delete if {
	evaluation.decision with input as {
		"subject": {"type": "user", "id": "root@acme.com", "properties": {"roles": ["admin"], "department": "security"}},
		"action": {"name": "can_delete"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

test_owner_can_edit if {
	evaluation.decision with input as {
		"subject": {"type": "user", "id": "alice@acme.com", "properties": {"roles": ["viewer"], "department": "eng"}},
		"action": {"name": "can_edit"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

test_editor_same_department_can_read if {
	evaluation.decision with input as {
		"subject": {"type": "user", "id": "bob@acme.com", "properties": {"roles": ["editor"], "department": "eng"}},
		"action": {"name": "can_read"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

test_anyone_can_read_public if {
	evaluation.decision with input as {
		"subject": {"type": "user", "id": "carol@acme.com", "properties": {"roles": ["viewer"], "department": "sales"}},
		"action": {"name": "can_read"},
		"resource": {"type": "document", "id": "doc-2", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "public"}},
		"context": {},
	}
}

# Deny cases (the ones that catch a false allow).

test_editor_other_department_cannot_edit if {
	not evaluation.decision with input as {
		"subject": {"type": "user", "id": "bob@acme.com", "properties": {"roles": ["editor"], "department": "sales"}},
		"action": {"name": "can_edit"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

test_editor_same_department_cannot_delete if {
	not evaluation.decision with input as {
		"subject": {"type": "user", "id": "bob@acme.com", "properties": {"roles": ["editor"], "department": "eng"}},
		"action": {"name": "can_delete"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

test_public_classification_does_not_allow_edit if {
	not evaluation.decision with input as {
		"subject": {"type": "user", "id": "carol@acme.com", "properties": {"roles": ["viewer"], "department": "sales"}},
		"action": {"name": "can_edit"},
		"resource": {"type": "document", "id": "doc-2", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "public"}},
		"context": {},
	}
}

test_viewer_no_relationship_cannot_read_internal if {
	not evaluation.decision with input as {
		"subject": {"type": "user", "id": "dave@acme.com", "properties": {"roles": ["viewer"], "department": "sales"}},
		"action": {"name": "can_read"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}

# The owner is limited to read/edit/delete. An action outside that set (here
# can_administer, which is not granted by any rule) must fall through to the
# default deny even for the owner. This is the test that catches the
# over-permissioning bug where the owner rule granted every action.
test_owner_cannot_perform_unlisted_action if {
	not evaluation.decision with input as {
		"subject": {"type": "user", "id": "alice@acme.com", "properties": {"roles": ["viewer"], "department": "eng"}},
		"action": {"name": "can_administer"},
		"resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
		"context": {},
	}
}
