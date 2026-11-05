# Lesson 4: PEP and fail-closed (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH; Python 3.10+. No accounts, no paid services.

## Task
Two fixes. (1) `starter/m4.rego` allows a read when `user.id` and `resource.owner` are equal but invalid (both null, false, 42, `{}`, `[]` or `""`). Require both to be non-empty strings. (2) `starter/pep_python.py` coerces `{"allow":"false"}` to allow and crashes on `[]`/`null`. Make `ask_pdp` deny on anything other than a JSON boolean `true` (missing, null, string, number, object, list, malformed JSON, non-200, timeout, unreachable).

## Run
```
cd starter
opa test m4.rego m4_test.rego m4_regression_test.rego -v; python3 pep_selftest.py
```
Starts **red** (Rego 5 pass, 6 fail of 11; pep_selftest 16 pass, 6 fail of 22). When you're done it should be **green** (Rego 11/11; pep_selftest 22 pass, 0 fail of 22). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).

Go option: in `solution/`, `go test ./...` runs the same decoder probes against `pep_go.go` (needs Go 1.21+).
