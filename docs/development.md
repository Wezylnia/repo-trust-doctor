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

## Design Rules

- Keep domain models free of infrastructure concerns.
- Keep analyzer logic out of CLI, API, and worker entry points.
- Keep scoring separate from analyzers.
- Keep policies separate from detection.
- Every meaningful finding needs evidence.
- Do not execute repository code by default.
- Analyzer failures should be isolated and visible in the report.

## Public Repository Notes

Local planning notes under `private-docs/` are intentionally ignored. Public documentation should live under `docs/` and be updated as behavior changes.
