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

The initial catalog covers the v0.1 static analyzers.

## Categories

- [Repository Health](repository-health.md)
- [GitHub Actions](github-actions.md)
- [Secrets](secrets.md)
- [Docker](docker.md)
