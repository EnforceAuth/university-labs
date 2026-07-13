# Lab: Answering an AuthZEN Evaluation

A runnable OPA lab for the "AuthZEN & PDP Integration" course. Real `opa`, no invented tooling.

This is a fill-in-the-blank lab. `policy.rego` ships as a default-deny **starter** with the decision logic left as a `TODO(learner)`. Your job is to implement it until the test suite passes.

## Files

- `policy.rego` — the **starter**. It answers an OpenID AuthZEN 1.0 evaluation, but only with `default decision := false`; the allow rules are a `TODO` you complete. The request body is `input`; the boolean result is `decision`.
- `policy_test.rego` — the graded test suite: four allow cases and five deny cases. Do not edit it; make it pass.

## AuthZEN request shape

The policy consumes an AuthZEN evaluation request as `input`:

```json
{
  "subject": {
    "type": "user",
    "id": "alice@acme.com",
    "properties": { "roles": ["editor"], "department": "eng" }
  },
  "action": { "name": "can_read" },
  "resource": {
    "type": "document",
    "id": "doc-1",
    "properties": {
      "owner": "alice@acme.com",
      "department": "eng",
      "classification": "internal"
    }
  },
  "context": {}
}
```

The AuthZEN response is `{"decision": true}`. In the lab that boolean is the `decision` rule.

## Rules

- Admins (`"admin"` in `subject.properties.roles`) may perform any action.
- The owner (`subject.id == resource.properties.owner`) may read, edit, or delete.
- An editor in the resource's department may read or edit.
- Anyone may read a resource classified `"public"`.
- Everything else falls through to the default deny.

## Run

From the cloned `university-labs` repo:

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
opa test courses/authzen-pdp-integration -v
```

On the untouched starter you get `PASS: 5/9` (the five deny cases pass; the four allow cases fail). Implement the `TODO(learner)` in `policy.rego` until you reach `PASS: 9/9`. Keep iterating until `opa test` is green.

Expected: `PASS: 9/9`.

## How the plugin uses this

`opa-authzen-plugin` extends OPA with the AuthZEN endpoints. When a PEP calls
`POST /access/v1/evaluation`, the plugin maps the request body onto `input`
(`input.subject`, `input.action`, `input.resource`, `input.context`) and
evaluates the Rego decision you configure. The single-request endpoint returns
one `{"decision": ...}`; the batch endpoint `POST /access/v1/evaluations`
returns one decision per item in the request. `GET /.well-known/authzen-configuration`
lets the PEP discover the PDP's endpoints. This lab is the decision the plugin
would evaluate; you exercise it directly with `opa test` so no server is needed.

Served concretely, the plugin is compiled into an OPA build and enabled through
OPA's configuration, which also binds it to the decision rule (for this lab,
`data.university.authzen.evaluation.decision`). You then start OPA in server mode
(`opa run --server`, stock OPA), and the plugin registers the AuthZEN routes on
top. A PEP calls the single-evaluation endpoint like this:

```bash
curl -s localhost:8181/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{
    "subject":  {"type": "user", "id": "alice@acme.com", "properties": {"roles": ["editor"], "department": "eng"}},
    "action":   {"name": "can_read"},
    "resource": {"type": "document", "id": "doc-1", "properties": {"owner": "alice@acme.com", "department": "eng", "classification": "internal"}},
    "context":  {}
  }'
# => {"decision": true}
```

Port 8181 is OPA's default server port. The exact config keys that enable the
plugin and bind the decision path live in the plugin's build/config and are
omitted here; the route, request shape, and response are the AuthZEN 1.0
contract.

## Exercise

**Primary task.** Implement the `decision` in `policy.rego` so the four allow tests pass while the five deny tests stay passing. The idiomatic shape is several small `allow if { ... }` rules OR-ed together, with `decision if allow`, one rule per bullet in the Rules section above (admin, owner, editor-in-department, public-read). Gate the `owner` rule to `can_read`/`can_edit`/`can_delete` so the owner is not silently granted every action. Run `opa test courses/authzen-pdp-integration -v` until you see `PASS: 9/9`.

**Stretch goals** (optional, once the suite is green):

1. Add an action `can_share` that only the owner or an admin may perform. The `owner` rule is gated to `can_read`/`can_edit`/`can_delete`, so the owner does not get `can_share` for free; you must grant it explicitly (admins already can, through the `admin` rule). Add one allow test proving the owner can `can_share` their own resource, and one deny test proving an editor in the resource's department cannot `can_share`.
2. Add a deny test proving an editor in the correct department still cannot `can_delete`. (One already exists. Write a second with a different department to be sure the department check, not luck, is what denies.)
3. Keep the suite green. If a change lets an editor delete, a deny test should fail. That is the point: the deny tests catch a false allow.
