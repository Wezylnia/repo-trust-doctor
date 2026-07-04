# CI Usage

Repository Trust Doctor can run as a static repository trust gate in CI. It does not execute scanned repository code by default.

## Score Gate

Fail the job when the score is below a minimum threshold:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --fail-under 75
```

## Severity Gate

Fail the job when any finding is at or above a severity:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --fail-on-severity High
```

Supported severities:

```text
Info
Low
Medium
High
Critical
```

## Report Artifact

Write a Markdown report for CI artifacts:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format markdown --output reports/repo-trust.md --force
```

For profile-specific local and CI examples, see [Scan Examples](examples.md).

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed and no configured gate failed |
| `1` | CLI usage error |
| `2` | Input/output error |
| `3` | Scan completed with `AvoidAsProductionDependency` decision |
| `4` | Configured CI gate failed |

## Safety Notes

- Do not add install, build, test, package-manager, or Docker execution steps for untrusted repositories as part of the scan.
- Treat reports as heuristic evidence, not a security certification.
- Prefer Markdown or JSON artifacts for manual review when a gate fails.
