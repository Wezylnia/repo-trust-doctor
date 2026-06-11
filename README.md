# Repository Trust Doctor

[![CI](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/Wezylnia/repo-trust-doctor?include_prereleases)](https://github.com/Wezylnia/repo-trust-doctor/releases)
[![Good First Issues](https://img.shields.io/github/issues/Wezylnia/repo-trust-doctor/good%20first%20issue)](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
[![Help Wanted](https://img.shields.io/github/issues/Wezylnia/repo-trust-doctor/help%20wanted)](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22)
[![License](https://img.shields.io/github/license/Wezylnia/repo-trust-doctor)](LICENSE)

Repository Trust Doctor is a modular repository analysis platform for deciding whether an open-source repository is healthy, maintainable, and trustworthy enough to use, contribute to, or depend on.

The project is intentionally evidence-based: analyzers produce findings with rule IDs, severity, confidence, evidence, and recommendations. Scoring and policy evaluation interpret those findings without hiding serious risks behind an average score.

## What It Checks Today

The stable `v1.1.0` release focuses on local, static repository trust signals:

- repository health files such as README, LICENSE, SECURITY.md, contributing docs, CODEOWNERS, templates, and changelog,
- GitHub Actions workflow risks such as broad permissions, `pull_request_target`, unpinned actions, shell pipe execution, and checkout credential persistence,
- possible committed secrets or sensitive files with redacted evidence,
- Dockerfile hygiene signals such as `latest` tags, missing `.dockerignore`, root user risk, missing healthcheck, secret-like `ENV`, and missing multi-stage builds,
- dependency lockfile coverage and static package-origin signals for npm, NuGet, Python, Maven, Gradle, and Spring Boot manifests/configuration,
- deterministic JSON, Markdown, and SARIF reports with stable finding fingerprints,
- release artifact checksum, SBOM/provenance, changelog, package-version, and release workflow evidence,
- deep scan coverage import, critical code heuristics, and .NET public API baseline review,
- trust diff between JSON scan reports with new/resolved/worsened/improved finding changes,
- a local-first React workbench for GitHub repository scans,
- CI gate behavior through score and severity thresholds.

## Current Status

This repository is at the `v1.1.0` milestone. It is a stable static repository trust platform intended for local repository trust review, repository hardening, CI gates, analyzer development, dependency inventory review, cautious package-origin review, policy-aware scoring, release trust review, deep code intelligence, trust change review, API/worker-hosted scan flows, and local React-backed scan review.

Implemented through `v1.1.0`:

- a clean .NET solution structure,
- pure domain models,
- analyzer abstractions,
- a shared application scan lifecycle with queue, status, cancellation, and progress models,
- a reusable repository scan runner used by CLI, API, and worker hosts,
- static-only scan orchestration,
- console, JSON, Markdown, and SARIF report output,
- a CLI-first workflow,
- minimal API scan endpoints for health, start, status, progress, modules, findings, report export, and cancellation,
- worker-based queued scan execution,
- a local React trust workbench that starts GitHub repository scans and opens completed reports directly,
- repository health, GitHub Actions, secret quick scan, Docker, and dependency lockfile analyzers,
- expanded repository documentation quality checks,
- expanded GitHub Actions release and artifact checks,
- expanded Docker cache and package-layering checks,
- structured npm, NuGet, Python, Maven, and Gradle dependency inventory artifacts,
- npm, NuGet, Python, Maven, and Gradle lockfile coverage checks,
- direct NuGet `PackageReference` parsing, including basic Central Package Management version resolution,
- `package.json` dependency section parsing for production, development, optional, and peer dependencies,
- conservative Python dependency parsing for `requirements.txt`, `pyproject.toml`, and `Pipfile`,
- Java dependency parsing for Maven `pom.xml`, Gradle `build.gradle`, and `build.gradle.kts`,
- Spring Boot Actuator exposure checks from static application configuration,
- static dependency hygiene findings for unpinned/ranged and prerelease versions,
- npm install-time script findings for manual review,
- NuGet package source recording from `NuGet.config` without network access,
- static package-origin findings for direct remote npm dependencies, local npm dependencies, insecure NuGet sources, and local NuGet sources,
- Markdown dependency inventory summaries,
- typed trust profiles recorded in reports,
- stable finding fingerprints for report output,
- CI gate options for score and severity thresholds,
- safe package metadata and OSV advisory lookup foundations,
- dependency freshness, vulnerability, license, package-origin, and dependency-confusion review findings,
- scan progress DTOs for API/worker/frontend polling,
- built-in trust policies and profile-aware scoring,
- release evidence checks for checksums, SBOM/provenance, changelog/package version alignment, and release workflows,
- coverage import for Cobertura XML and lcov in deep scans,
- critical code heuristics for auth, authorization, payments, data access, file operations, network calls, cryptography, secrets, large files, and broad exception handling,
- low or missing coverage correlation for critical code,
- .NET public API surface extraction and baseline diff review,
- scan snapshot, trust diff, repository comparison, scheduled scan, and regression alert models,
- CLI `diff` command for comparing two JSON scan reports,
- fixture-based analyzer tests,
- public rule, architecture, API/worker, security, web UI, and contributor documentation.

The scanner does not execute repository code by default. Persistence, hosted monitoring, and notification providers are planned future work.

## Requirements

- .NET 10 SDK or newer.
- Git.

## Install From Source

```text
git clone https://github.com/Wezylnia/repo-trust-doctor.git
cd repo-trust-doctor
dotnet restore
dotnet build
```

## Quick Start

Run a local static scan:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format console
```

Export a Markdown report:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
```

## Web Trust Workbench

The React workbench starts GitHub repository scans through the local API backend and opens completed reports directly. The user enters a repository as `owner/repo`; the UI sends `https://github.com/owner/repo` to the backend.

```text
dotnet run --project src/Apps/RepoTrustDoctor.Api --urls http://localhost:5000

cd src/Apps/RepoTrustDoctor.Web
npm install
npm run dev
```

## API And Worker

Run the local API host:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Api
```

Start and poll a scan:

```text
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d "{\"target\":\".\",\"depth\":\"standard\",\"trustProfile\":\"production\"}"

curl http://localhost:5000/api/scans/{scanId}
curl http://localhost:5000/api/scans/{scanId}/progress
curl http://localhost:5000/api/scans/{scanId}/report?format=json
```

The worker host uses the same application scan lifecycle and repository scan runner as the API:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Worker
```

The current API and worker use in-memory scan state and queue implementations. They are intended for local development, integration tests, and future persistence integration.

## Contributing

Contributor help is very welcome. The project has scoped dependency intelligence and reporting issues ready for external contributors:

- [good first issue](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
- [help wanted](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22)
- [contributor-ready](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3Acontributor-ready)

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, safety rules, validation commands, and pull request expectations. Use [Discussions](https://github.com/Wezylnia/repo-trust-doctor/discussions) for questions or help choosing an issue.

## CLI

The CLI supports local path scans and shallow cloning for public HTTP(S) Git repository URLs:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan .
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan https://github.com/owner/repo
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format sarif --output reports/scan.sarif
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md --force
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --depth deep --format markdown
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff reports/before.json reports/after.json --format markdown
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile enterprise
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --fail-under 75
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --fail-on-severity High
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- --version
```

Supported trust profiles are `Personal`, `ProductionDependency`, and `SecuritySensitiveDependency`. The CLI still accepts compatibility aliases such as `enterprise`, `ci-cd`, and `container` and normalizes them before policy evaluation.

### CLI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed and no blocking avoid decision |
| `1`  | CLI usage error |
| `2`  | Input/output error (e.g. refusing to overwrite an existing report) |
| `3`  | Scan completed with `AvoidAsProductionDependency` decision |
| `4`  | Configured CI gate failed |

Future packaged CLI commands:

```text
repo-trust-doctor scan .
repo-trust-doctor scan https://github.com/owner/repo
repo-trust-doctor scan . --format json
repo-trust-doctor scan . --format markdown
repo-trust-doctor scan . --format sarif
repo-trust-doctor scan . --format json --output report.json
repo-trust-doctor diff before.json after.json --format markdown --output diff.md
```

## Architecture

The architecture separates detection from interpretation:

- `src/Apps` contains executable entry points such as the CLI, API, and worker.
- `src/Apps/RepoTrustDoctor.Web` contains the local React report viewer.
- `src/Core` contains domain, application, contracts, and shared primitives.
- `src/Engine` contains analyzer abstractions, execution, orchestration, scoring, policies, and reporting.
- `src/Analyzers` contains independent analyzer modules.
- `src/Infrastructure` contains Git, package registry, security feed, scan runner, and future persistence/caching integrations.
- `src/Infrastructure/RepoTrustDoctor.Infrastructure.Git` currently prepares local workspaces and shallow-clones public HTTP(S) Git URLs.
- `src/Infrastructure/RepoTrustDoctor.Infrastructure.Scanning` composes the default analyzer pipeline for CLI, API, and worker hosts.
- `tests` contains unit, analyzer, integration, and fixture-based tests.

Read the public architecture overview in [docs/architecture.md](docs/architecture.md).

## Roadmap

The roadmap grows the platform gradually:

| Version | Focus |
| ------- | ----- |
| `v0.1.x` | Foundation alpha, static local scans, basic analyzers, report output, CI gates |
| `v0.2.x` | Static analyzer expansion for repository docs, workflows, secrets, Docker, and reports |
| `v0.3.x` | Structured dependency inventory for NuGet, npm, and Python |
| `v0.4.x` | Risk intelligence for dependency metadata, vulnerabilities, licenses, and origin signals |
| `v0.5.x` | SARIF output and progressive scan contracts |
| `v0.6.x` | Built-in policies, blocking risks, and profile-aware scoring |
| `v0.7.x` | Release hygiene, artifact integrity, SBOM/provenance, and supply-chain evidence |
| `v0.8.x` | Coverage import, code criticality, public API analysis, and deep scan signals |
| `v0.9.x` | Trust history, comparison, trust diff, and monitoring models |
| `v1.0.x` | Current: stable public platform with documented contracts, CLI/API/worker hosts, React scan workbench, and reliable reports |
| `v1.1.0` | Java and Spring Boot dependency support, plus continued React/backend scan experience |

See [docs/roadmap.md](docs/roadmap.md) for detailed milestone scope, out-of-scope boundaries, and success criteria.

## Safety Principles

- Do not execute untrusted repository code by default.
- Prefer static parsing and metadata lookups.
- Redact possible secrets in evidence.
- Isolate analyzer failures so partial reports remain useful.
- Use cautious language for heuristic findings.
- Do not accept arbitrary uploaded files without an explicit intake policy.
- Refuse report overwrites unless `--force` is provided.

## Documentation

- [Architecture](docs/architecture.md)
- [Analyzer coverage](docs/analyzers.md)
- [Roadmap](docs/roadmap.md)
- [Development guide](docs/development.md)
- [CI usage](docs/ci-usage.md)
- [Analyzer authoring guide](docs/analyzer-authoring.md)
- [Report format](docs/report-format.md)
- [API and worker](docs/api-worker.md)
- [Trust history and diff](docs/trust-history.md)
- [Web UI](docs/web-ui.md)
- [Release checklist](docs/release-checklist.md)
- [Trust profiles](docs/policies/trust-profiles.md)
- [Rule catalog](docs/rules/README.md)
- [Changelog](CHANGELOG.md)

## Repository Governance

The public repository uses protected `main`, required pull request review for non-admin contributors, required CI status checks, CodeQL, OSSF Scorecard, Dependabot, and Copilot review instructions. Repository admins can bypass branch protection for urgent maintenance.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.

## Disclaimer

repo-trust-doctor provides heuristic, evidence-based repository analysis. It does not certify that a repository, dependency, workflow, package, or release is secure, safe, compliant, or free from vulnerabilities.

Reports may contain false positives or false negatives. The tool is intended to support decision-making and does not replace manual review, legal review, security testing, or professional audit.
