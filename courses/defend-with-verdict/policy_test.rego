package university.verdict.approvals_test

import data.university.verdict.approvals

# Allow cases.

test_low_risk_action_runs_without_approval if {
	approvals.allow with input as {
		"agent": {"id": "agent-legal-assistant"},
		"action": {"name": "read_matter", "risk": "low"},
		"resource": {"kind": "record"},
		"approval": {"present": false},
		"now": 1000,
	}
}

test_high_risk_action_allowed_with_valid_human_approval if {
	approvals.allow with input as {
		"agent": {"id": "agent-legal-assistant"},
		"action": {"name": "send_wire_transfer", "risk": "high"},
		"resource": {"kind": "payment"},
		"approval": {
			"present": true,
			"approver_type": "human",
			"approver": "cfo@example.com",
			"scope_action": "send_wire_transfer",
			"expires_at": 2000,
		},
		"now": 1000,
	}
}

test_second_high_risk_action_allowed_with_scoped_approval if {
	approvals.allow with input as {
		"agent": {"id": "agent-ops"},
		"action": {"name": "delete_backup", "risk": "high"},
		"resource": {"kind": "backup"},
		"approval": {
			"present": true,
			"approver_type": "human",
			"approver": "sre-oncall@example.com",
			"scope_action": "delete_backup",
			"expires_at": 5000,
		},
		"now": 4999,
	}
}

# Deny cases (the ones that catch a false allow).

# The Politeness Trap: the agent asks nicely but carries no external approval.
test_high_risk_action_denied_without_approval if {
	not approvals.allow with input as {
		"agent": {"id": "agent-legal-assistant"},
		"action": {"name": "send_wire_transfer", "risk": "high"},
		"resource": {"kind": "payment"},
		"approval": {"present": false},
		"now": 1000,
	}
}

# An agent cannot approve its own sensitive action.
test_high_risk_action_denied_on_agent_self_approval if {
	not approvals.allow with input as {
		"agent": {"id": "agent-legal-assistant"},
		"action": {"name": "send_wire_transfer", "risk": "high"},
		"resource": {"kind": "payment"},
		"approval": {
			"present": true,
			"approver_type": "agent",
			"approver": "agent-legal-assistant",
			"scope_action": "send_wire_transfer",
			"expires_at": 2000,
		},
		"now": 1000,
	}
}

# An expired approval no longer authorizes the action.
test_high_risk_action_denied_on_expired_approval if {
	not approvals.allow with input as {
		"agent": {"id": "agent-ops"},
		"action": {"name": "delete_backup", "risk": "high"},
		"resource": {"kind": "backup"},
		"approval": {
			"present": true,
			"approver_type": "human",
			"approver": "sre-oncall@example.com",
			"scope_action": "delete_backup",
			"expires_at": 4000,
		},
		"now": 4001,
	}
}

# An approval scoped to a different action does not authorize this one.
test_high_risk_action_denied_on_scope_mismatch if {
	not approvals.allow with input as {
		"agent": {"id": "agent-legal-assistant"},
		"action": {"name": "send_wire_transfer", "risk": "high"},
		"resource": {"kind": "payment"},
		"approval": {
			"present": true,
			"approver_type": "human",
			"approver": "cfo@example.com",
			"scope_action": "read_matter",
			"expires_at": 2000,
		},
		"now": 1000,
	}
}
