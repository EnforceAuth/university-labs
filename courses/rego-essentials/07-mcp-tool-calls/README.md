# Lesson 7: Authorizing MCP tool calls (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m7.rego` allows refunds with `null`, `false`, or negative amounts, and delegates that are `null`, `false`, numbers, or objects. Add explicit type and range checks (`is_number`, `is_string`, `is_array`) and reasons. Note: a non-empty delegate string still does not prove real delegated authority; the PEP must supply trusted delegation context.

## Run
```
cd starter
opa test m7.rego m7_test.rego m7_regression_test.rego m7_delegation.rego m7_delegation_test.rego -v
```
Starts **red** (25 pass, 9 fail of 34). When you're done it should be **green** (34/34). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).

Separate active-grant example: `m7_delegation.rego` checks a trusted grant list in `data` (status `active`, `expires_at_ns` later than `time.now_ns()`, matching agent, user and tool), and `refund_allowed` requires both `m7.allow` and `delegation_ok` on the same input. It does not prove the trusted grant records are genuine. 14 tests, green in both folders.
