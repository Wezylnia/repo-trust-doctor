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

The current catalog covers implemented static analyzer rules, dependency inventory rules, and the first static package-origin review rules. Future releases will add package metadata, vulnerability, license, typosquatting, dependency confusion, and policy rules.

## Categories

- [Repository Health](repository-health.md)
- [GitHub Actions](github-actions.md)
- [Secrets](secrets.md)
- [Docker](docker.md)
- [Dependencies](dependencies.md)
