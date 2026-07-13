package university.lifecycle.promotion_test

import data.university.lifecycle.promotion

# Allow cases.

test_engineer_can_promote_dev if {
	promotion.allow with input as {
		"subject": {"role": "engineer"},
		"action": "promote",
		"target": {"environment": "dev", "bundle": "authz-core"},
		"change": {"approved": false, "commit_sha": "a1b2c3d"},
	}
}

test_release_manager_can_promote_prod_when_approved if {
	promotion.allow with input as {
		"subject": {"role": "release-manager"},
		"action": "promote",
		"target": {"environment": "prod", "bundle": "authz-core"},
		"change": {"approved": true, "commit_sha": "a1b2c3d"},
	}
}

test_release_manager_can_rollback_prod_by_prior_commit if {
	promotion.allow with input as {
		"subject": {"role": "release-manager"},
		"action": "rollback",
		"target": {"environment": "prod", "bundle": "authz-core"},
		"change": {"approved": false, "commit_sha": "9f8e7d6"},
	}
}

# Deny cases (the ones that catch a false allow).

test_engineer_cannot_promote_prod if {
	not promotion.allow with input as {
		"subject": {"role": "engineer"},
		"action": "promote",
		"target": {"environment": "prod", "bundle": "authz-core"},
		"change": {"approved": true, "commit_sha": "a1b2c3d"},
	}
}

test_release_manager_cannot_promote_prod_unapproved if {
	not promotion.allow with input as {
		"subject": {"role": "release-manager"},
		"action": "promote",
		"target": {"environment": "prod", "bundle": "authz-core"},
		"change": {"approved": false, "commit_sha": "a1b2c3d"},
	}
}

test_promote_dev_without_commit_is_denied if {
	not promotion.allow with input as {
		"subject": {"role": "engineer"},
		"action": "promote",
		"target": {"environment": "dev", "bundle": "authz-core"},
		"change": {"approved": false, "commit_sha": ""},
	}
}

# A role outside the deployer set cannot promote, even to dev with a commit.
# This proves the dev rule gates on role, not just on a pinned commit_sha.
test_non_deployer_role_cannot_promote_dev if {
	not promotion.allow with input as {
		"subject": {"role": "intern"},
		"action": "promote",
		"target": {"environment": "dev", "bundle": "authz-core"},
		"change": {"approved": false, "commit_sha": "a1b2c3d"},
	}
}
