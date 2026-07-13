package university.opa_eopa.fundamentals_test

import data.university.opa_eopa.fundamentals

# Allow cases.

test_write_account_can_post if {
	fundamentals.allow with input as {"subject": {"account": "svc-checkout"}, "method": "POST"}
}

test_write_account_can_read if {
	fundamentals.allow with input as {"subject": {"account": "svc-billing"}, "method": "HEAD"}
}

test_read_account_can_get if {
	fundamentals.allow with input as {"subject": {"account": "svc-reporting"}, "method": "GET"}
}

# Deny cases (the ones that catch a false allow).

test_read_account_cannot_post if {
	not fundamentals.allow with input as {"subject": {"account": "svc-reporting"}, "method": "POST"}
}

test_read_account_cannot_delete if {
	not fundamentals.allow with input as {"subject": {"account": "svc-audit"}, "method": "DELETE"}
}

test_unknown_account_denied if {
	not fundamentals.allow with input as {"subject": {"account": "svc-unknown"}, "method": "GET"}
}
