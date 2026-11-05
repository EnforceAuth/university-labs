# Lesson 1: Rego basics (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m1.rego` checks the wrong role in `is_admin`. Fix it so admins (and only admins) match.

## Run
```
cd starter
opa test m1.rego m1_test.rego -v
```
Starts **red** (2 pass, 2 fail of 4). When you're done it should be **green** (4/4). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).
