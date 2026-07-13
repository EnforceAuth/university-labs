package university.grc.authz

# A teaching policy for the "Decision Logs, Continuous Authorization &
# Compliance Evidence" course. It models a clinical-record access decision and,
# unlike a bare boolean rule, returns a STRUCTURED decision document. That
# structure is what a Policy Decision Point (OPA or Enterprise OPA) emits and
# what a decision log records: not just allow/deny, but the reason and any
# obligations. EnforceAuth's Writ control plane collects and replays decision
# logs like these; Writ is not a PDP on the request path.
#
# Input shape:
#   {
#     "subject":  {"id": "...", "role": "...", "care_teams": ["..."], "ssn": "..."},
#     "action":   "read",
#     "resource": {"type": "record", "care_team": "...", "mrn": "..."},
#     "context":  {"justification": "..."}
#   }
#
# Rules modeled:
#   - A clinician may read a record when the record's care_team is one of the
#     subject's care_teams (a minimum-necessary style check).
#   - Break-glass: an emergency clinician who is NOT on the care team may still
#     read, but only with a non-empty justification, and the decision then
#     carries an obligation to notify the privacy officer.
# Everything else falls through to the default deny.

default allow := false

# The request is allowed exactly when the policy produced an authorizing
# reason. These two lines are already wired for you; your job is to make
# `reason` take the right value below.
allow if reason == "care-team-match"

allow if reason == "break-glass"

# TODO(learner): implement the two authorizing `reason` rules.
#
# Right now `reason` only ever falls through to the default
# "deny-no-authorization" below, so `allow` is always false and the two
# allow-case tests fail. Add the incremental `reason := ...` rules that make
# them pass, using the `in` operator for the care-team membership check.
#
#   1) reason := "care-team-match" when:
#        - input.action == "read"
#        - input.resource.care_team is one of input.subject.care_teams
#
#   2) reason := "break-glass" when (emergency override):
#        - input.action == "read"
#        - input.subject.role == "emergency"
#        - input.context.justification != ""
#        - input.resource.care_team is NOT one of input.subject.care_teams
#
# `reason` is single-valued, so guard the break-glass body with the negated
# membership check above; otherwise the two rules can both fire on one input
# and OPA reports a complete-rule conflict. The reference solution is in
# Solutions are not published. Iterate until opa test is green.

default reason := "deny-no-authorization"

# Obligations a Policy Enforcement Point must carry out when it honors the
# decision. Break-glass access is allowed but must be reported.
obligations contains "notify-privacy-officer" if {
	reason == "break-glass"
}

# The structured decision. This is the object worth logging: the outcome plus
# the reason and obligations that make it auditable and replayable later.
decision := {
	"allow": allow,
	"policy_id": "clinical-access-v1",
	"reason": reason,
	"obligations": obligations,
}
