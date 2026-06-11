# Rule Catalog

Rules follow this identifier format:

```text
TRUST-{CATEGORY}{NUMBER}
```

Each rule documents:

- title,
- category,
- default severity,
- default confidence,
- what is detected,
- why it matters,
- recommendation.

The current catalog covers implemented static analyzer rules, dependency inventory rules, dependency risk intelligence, vulnerability advisory findings, license metadata review, package-origin review rules, release evidence rules, and deep code intelligence rules.

See also [Analyzer Coverage](../analyzers.md) for a short description of each analysis module and [Language Support](../language-support.md) for ecosystem coverage by language and package manager.

## Categories

- [Repository Health](repository-health.md)
- [GitHub Actions](github-actions.md)
- [Secrets](secrets.md)
- [Docker](docker.md)
- [Dependencies](dependencies.md)
- [Licenses](licenses.md)
- [Vulnerabilities](vulnerabilities.md)
- [Releases](releases.md)
- [Codebase](codebase.md)
- [GitLab CI](gitlab-ci.md)
- [Kubernetes](kubernetes.md)
