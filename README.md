# EnforceAuth University Labs

Hands-on OPA lab starters for [EnforceAuth University](https://university.enforceauth.dev).

These are the learner-facing starters only. Solutions are not published. Iterate until opa test is green.

## Prerequisites

Install the [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa):

```bash
# macOS (Homebrew)
brew install opa

# Or download a release binary from GitHub
# https://github.com/open-policy-agent/opa/releases
```

Confirm with `opa version`.

## Clone

```bash
git clone https://github.com/EnforceAuth/university-labs.git
cd university-labs
```

## Run a lab

Each course lives under `courses/<course-id>/`. From the repo root:

```bash
opa test courses/foundations-authorization-gap -v
```

Starter policies ship intentionally incomplete (red). Implement the `# TODO(learner)` blocks until the suite is green.

## Courses

- `courses/assess-with-zift/`
- `courses/authzen-pdp-integration/`
- `courses/capstone-four-product-fabric/`
- `courses/decision-logs-and-compliance-evidence/`
- `courses/defend-with-verdict/`
- `courses/evaluate-with-herald/`
- `courses/foundations-authorization-gap/`
- `courses/getting-started-writ-control-plane/`
- `courses/govern-with-writ/`
- `courses/migrating-to-enforceauth/`
- `courses/opa-eopa-fundamentals/`
- `courses/policy-lifecycle-build-promote-rollback/`
- `courses/reference-architectures/`
- `courses/reference-hello-authorization/`

## Course lessons

Lab context, lessons, and the rest of the curriculum live on the University site:

https://university.enforceauth.dev

## License

Apache License 2.0. See [LICENSE](./LICENSE).
