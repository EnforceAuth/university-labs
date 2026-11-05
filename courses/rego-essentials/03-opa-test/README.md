# Lesson 3: Testing with opa test (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m2.rego` grants every non-guest role everything. The deny tests catch it. Replace the buggy rule with the two narrow rules from lesson 2.

## Run
```
cd starter
opa test m2.rego m3_test.rego -v
```
Starts **red** (3 pass, 2 fail of 5). When you're done it should be **green** (5/5). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).
