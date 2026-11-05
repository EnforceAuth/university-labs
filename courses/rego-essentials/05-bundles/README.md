# Lesson 5: Bundles and environments (DRAFT lab, not published)
**Pinned:** OPA 1.22.0 (static binary) on PATH. No accounts, no paid services.

## Task
`starter/m5.rego` relaxes rules with `env != "prod"`, so an unlisted env `prod2` is treated as safe. Replace it with an explicit allow list. Then build one bundle per environment from the same Rego revision:

```
opa build m5.rego env/staging/data.json --revision v42-staging -o /tmp/rego-lesson5-staging.tar.gz
opa build m5.rego env/prod/data.json --revision v42-prod -o /tmp/rego-lesson5-prod.tar.gz
printf '%s' '{"action":"deploy","user":{"role":"developer"}}' | opa eval -b /tmp/rego-lesson5-staging.tar.gz --stdin-input -f raw data.rego_essentials.m5.allow   # true
```
Same command against the prod bundle prints `false`.

## Run
```
cd starter
opa test m5.rego m5_test.rego -v
```
Starts **red** (4 pass, 1 fail of 5). When you're done it should be **green** (5/5). `solution/` has the reference answer.

From this lesson folder, run `bash ../run_labs.sh` to verify every lab (or `bash run_labs.sh` from `labs/`).
