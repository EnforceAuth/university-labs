# Lesson 2: First allow/deny policy (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m2.rego` has default deny and a read rule. Add the narrow rule that lets editors (only) write.

## Run
```
cd starter
opa test m2.rego m3_test.rego -v
```
Starts **red** (4 pass, 1 fail of 5). When you're done it should be **green** (5/5). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).
