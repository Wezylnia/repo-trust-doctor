# Scan Examples

These examples show common local review flows. Scans are static by default: they do not install packages, run builds, execute tests, or start containers in the repository being reviewed.

## Personal Review

Use the `Personal` profile for experiments, learning projects, and low-impact local tools:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile Personal --format markdown --output reports/personal-review.md --force
```

Expect a permissive decision model. The report still lists high-signal risks such as committed secrets, unsafe release workflows, and missing license evidence, but lower-impact hygiene findings carry less policy weight than they do in stricter profiles.

## Production Dependency Review

Use the `ProductionDependency` profile before depending on a library, tool, service, or base repository in production:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile ProductionDependency --format json --output reports/production-review.json --force
```

Review the final decision, category scores, blocking risks, and top findings together. A repository can have the same findings as a personal scan but receive stricter warnings or violations because production use weighs dependency, release, security, and maintenance signals more heavily.

## Security-Sensitive Dependency Review

Use the `SecuritySensitiveDependency` profile for authentication, authorization, cryptography, secret-handling, organization-wide tooling, and security-control dependencies:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile SecuritySensitiveDependency --depth deep --format sarif --output reports/security-sensitive.sarif --force
```

This profile applies the strictest policy interpretation. Missing security policy, serious vulnerability evidence, unpinned external actions, weak release checksums, and low category scores are more likely to affect the decision.

## CI Gate With Artifacts

In CI, keep the scan static and publish the report that best fits your review workflow:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile ProductionDependency --fail-under 75 --fail-on-severity High --format markdown --output reports/repo-trust.md --force
```

Use JSON for automation, Markdown for human review, and SARIF for code-scanning integrations. Scores are intentionally not exact promises across versions; compare decisions, category movement, and findings when upgrading.
