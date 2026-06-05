# Development Guide

## Requirements

- .NET 10 SDK or newer.
- Git.

The repository targets .NET 10 for the initial implementation.

## Build

```powershell
dotnet restore
dotnet build
```

## Test

```powershell
dotnet test
```

## Local CLI Smoke Test

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format console
```

To scan a public Git repository URL:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan https://github.com/owner/repo --format console
```

To write a report to disk:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
```

Existing report files are not overwritten unless `--force` is supplied.

Trust profile values are normalized by the CLI. Canonical values are `Personal`, `ProductionDependency`, `EnterpriseDependency`, `CiCdTool`, `SecuritySensitiveDependency`, and `ContainerDependency`; common aliases such as `production`, `enterprise`, `ci-cd`, `security`, and `container` are also accepted.

## Dependency Analyzer Fixtures

Dependency analyzer tests should prefer small synthetic fixtures for NuGet, npm, and Python manifests. Fixtures must not include real credentials, internal registry URLs, customer data, or generated lockfiles larger than the test actually needs.

Static dependency tests may parse manifests and lockfiles, but they must not run package managers such as `npm install`, `dotnet restore`, `pip install`, Poetry, uv, or Pipenv against scanned repository content.

## CLI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed, no blocking decision |
| `1`  | CLI usage error |
| `2`  | Input/output error |
| `3`  | Scan completed with `AvoidAsProductionDependency` |
| `4`  | Configured CI gate failed |

## Design Rules

- Keep domain models free of infrastructure concerns.
- Keep analyzer logic out of CLI, API, and worker entry points.
- Keep scoring separate from analyzers.
- Keep policies separate from detection.
- Every meaningful finding needs evidence.
- Do not execute repository code by default.
- Analyzer failures should be isolated and visible in the report.

## Pull Request Checks

Pull requests to `main` are expected to pass:

- `build-test`
- `repo-trust-scan`
- CodeQL analysis

The protected branch requires review before merge for non-admin contributors. Repository admins can bypass branch protection for urgent maintenance. GitHub Copilot review can be requested manually from the pull request reviewers menu, and the repository also has an automatic Copilot review ruleset for pull requests targeting `main`.

## Public Repository Notes

Local planning notes under `private-docs/` are intentionally ignored. Public documentation should live under `docs/` and be updated as behavior changes.
