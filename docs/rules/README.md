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

The current catalog covers implemented static analyzer rules and the first dependency inventory rules. Future releases will add package metadata, vulnerability, license, package origin, and policy rules.

## Categories

- [Repository Health](repository-health.md)
- [GitHub Actions](github-actions.md)
- [Secrets](secrets.md)
- [Docker](docker.md)
- [Dependencies](dependencies.md)
