# Lesson 6: Decision logs and masking (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m6_mask.rego` masks email but not the card number. Add the mask. Then run `opa run --server --addr 127.0.0.1:8181 --config-file opa-config.yaml m4.rego m6_mask.rego`, POST lesson-4 input with `email` and `tool.arguments.card_number` added, and confirm both are absent from the console event and listed under `erased`.

## Run
```
cd starter
opa test m6_mask.rego m6_mask_test.rego m4.rego m4_test.rego m4_regression_test.rego -v
```
Starts **red** (12 pass, 1 fail of 13: the missing mask; the 11 ownership tests on the shipped `m4.rego` already pass). When you're done it should be **green** (13/13). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).
