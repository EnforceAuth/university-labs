package system.log_test

import rego.v1

import data.system.log

test_email_is_masked if {
	"/input/user/email" in log.mask
}

test_card_number_is_masked if {
	"/input/tool/arguments/card_number" in log.mask
}
