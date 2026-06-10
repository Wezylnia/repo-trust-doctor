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

The current catalog covers implemented static analyzer rules, dependency inventory rules, dependency risk intelligence, vulnerability advisory findings, license metadata review, and package-origin review rules.

## Categories

- [Repository Health](repository-health.md)
- [GitHub Actions](github-actions.md)
- [Secrets](secrets.md)
- [Docker](docker.md)
- [Dependencies](dependencies.md)
- [Licenses](licenses.md)
- [Vulnerabilities](vulnerabilities.md)
- [Releases](releases.md)
