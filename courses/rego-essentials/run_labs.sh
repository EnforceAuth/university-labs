#!/usr/bin/env bash
# Verifies every lab: starter must be RED, solution must be GREEN. Needs OPA 1.22.0 on PATH (python3 for lab 04).
cd "$(dirname "$0")"; rc=0
# Source tree only: stale-copy guard (not shipped in the learner package)
if [ -x ../tools/sync_check.sh ]; then ../tools/sync_check.sh || rc=1; fi
check(){ # dir kind
  local d=$1 k=$2 out ok
  if [ "$d" = 04-pep-fail-closed ]; then
    out=$( (cd $d/$k && r=0; opa test m4.rego m4_test.rego m4_regression_test.rego || r=1; python3 pep_selftest.py || r=1; if [ $k = solution ] && command -v go >/dev/null; then go test ./... || r=1; fi; exit $r) 2>&1); ok=$?
  else
    out=$(cd $d/$k && opa test $(ls *.rego) 2>&1); ok=$?
  fi
  local sum=$(echo "$out" | grep -E '^(PASS|FAIL):|^ok' | tr '\n' ' ')
  if [ $k = starter ]; then [ $ok -ne 0 ] && echo "$d starter RED  ($sum) OK" || { echo "$d starter NOT RED"; rc=1; }
  else [ $ok -eq 0 ] && echo "$d solution GREEN ($sum) OK" || { echo "$d solution NOT GREEN: $out"; rc=1; }; fi
}
for d in 0*/; do d=${d%/}; check $d starter; check $d solution; done
# Lab 05 build: one Rego revision, one bundle per environment
for e in staging prod; do (cd 05-bundles/solution && opa build m5.rego env/$e/data.json --revision "v42-$e" -o /tmp/rego-lesson5-$e.tar.gz) || rc=1; done
for e in staging prod; do echo -n "05 build $e developer/deploy -> "; printf '%s' '{"action":"deploy","user":{"role":"developer"}}' | opa eval -b /tmp/rego-lesson5-$e.tar.gz --stdin-input -f raw data.rego_essentials.m5.allow; done
exit $rc
