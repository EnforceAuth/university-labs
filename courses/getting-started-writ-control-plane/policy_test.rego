package university.gettingstarted.writ_test

import data.university.gettingstarted.writ

# Allow cases: one per hierarchy level, widest scope to narrowest.

# Tenant-scoped: admin may act anywhere in the tenant, even a different org/system/app.
test_same_tenant_admin_can_delete if {
	writ.allow with input as {
		"subject": {"role": "admin", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "delete",
		"resource": {"kind": "policy", "tenant": "acme", "org": "data", "system": "lake", "app": "ingest"},
	}
}

# Org-scoped: publisher may publish in the same org, even a different system/app.
test_same_org_publisher_can_publish if {
	writ.allow with input as {
		"subject": {"role": "publisher", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "publish",
		"resource": {"kind": "bundle", "tenant": "acme", "org": "payments", "system": "gateway", "app": "checkout"},
	}
}

# System-scoped: operator may restart in the same system, even a different app.
test_same_system_operator_can_restart if {
	writ.allow with input as {
		"subject": {"role": "operator", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "restart",
		"resource": {"kind": "service", "tenant": "acme", "org": "payments", "system": "ledger", "app": "reconcile"},
	}
}

# App-scoped: member may read only within the same app.
test_same_app_member_can_read if {
	writ.allow with input as {
		"subject": {"role": "member", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "read",
		"resource": {"kind": "report", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
	}
}

# Deny cases: one boundary per level (the ones that catch a false allow).

# Tenant boundary: a cross-tenant admin is denied even though the role is privileged.
test_cross_tenant_admin_denied if {
	not writ.allow with input as {
		"subject": {"role": "admin", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "delete",
		"resource": {"kind": "policy", "tenant": "globex", "org": "payments", "system": "ledger", "app": "postings"},
	}
}

# Org boundary: a cross-org publisher is denied (publisher is org-scoped, not tenant-scoped).
test_cross_org_publisher_cannot_publish if {
	not writ.allow with input as {
		"subject": {"role": "publisher", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "publish",
		"resource": {"kind": "bundle", "tenant": "acme", "org": "data", "system": "ledger", "app": "postings"},
	}
}

# System boundary: a cross-system operator is denied (operator is system-scoped).
test_cross_system_operator_cannot_restart if {
	not writ.allow with input as {
		"subject": {"role": "operator", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "restart",
		"resource": {"kind": "service", "tenant": "acme", "org": "payments", "system": "gateway", "app": "postings"},
	}
}

# App boundary: a cross-app member is denied read (member is app-scoped, the narrowest).
test_cross_app_member_cannot_read if {
	not writ.allow with input as {
		"subject": {"role": "member", "tenant": "acme", "org": "payments", "system": "ledger", "app": "postings"},
		"action": "read",
		"resource": {"kind": "report", "tenant": "acme", "org": "payments", "system": "ledger", "app": "reconcile"},
	}
}
