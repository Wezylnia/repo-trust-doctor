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

The current `v0.9.5` development line focuses on local, static repository trust signals across 12 package ecosystems, CI/CD pipeline security, infrastructure-as-code checks, and deep code intelligence:

- repository health files such as README, LICENSE, SECURITY.md, contributing docs, CODEOWNERS, templates, and changelog,
- GitHub Actions workflow risks such as broad permissions, `pull_request_target`, unpinned actions, shell pipe execution, checkout credential persistence, and advanced hardening rules,
- GitLab CI security checks for remote includes, CI variable injection, unpinned images, Docker-in-Docker, and broad cache paths,
- Azure Pipelines security checks for PR variable expansion, persisted credentials, unpinned images, and self-hosted pools,
- CircleCI security checks for unpinned orbs, Docker executor images, workspace persistence, and inline secrets,
- possible committed secrets or sensitive files with redacted evidence and reduced false positives,
- Dockerfile hygiene signals such as `latest` tags, missing `.dockerignore`, root user risk, missing healthcheck, secret-like `ENV`, and missing multi-stage builds,
- Docker Compose security checks for privileged mode, host network, Docker socket mounts, and .env file loading,
- Kubernetes manifest checks for privileged containers, host namespace sharing, hostPath volumes, broad capabilities, and privilege escalation,
- Terraform infrastructure checks for public ingress, wildcard IAM, public S3 ACLs, missing encryption, and provider version constraints,
- package registry configuration checks for HTTP registries, inline credentials, and insecure protocols,
- dependency lockfile coverage and static package-origin signals for npm, NuGet, Python, Maven, Gradle (including version catalogs), Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++,
- Spring Boot Actuator exposure and configuration analysis,
- deterministic JSON, Markdown, and SARIF reports with stable finding fingerprints,
- release artifact checksum, SBOM/provenance validation, changelog, package-version, release workflow evidence, and SBOM correlation,
- deep scan coverage import, critical code heuristics, multi-language public API extraction, import graph analysis, and framework route detection,
- trust diff between JSON scan reports with new/resolved/worsened/improved finding changes,
- a local-first React workbench for GitHub repository scans,
- CI gate behavior through score and severity thresholds.

## Current Status

This repository is at the `v0.9.5` development milestone. It is a stable static repository trust platform intended for local repository trust review, repository hardening, CI gates, analyzer development, dependency inventory review, policy-aware scoring, release trust review, deep code intelligence, trust change review, API/worker-hosted scan flows, and local React-backed scan review.

Key capabilities in `v0.9.5`:

- **Dependency consistency**: workspace-wide checks for major-version drift, source-kind drift, and lockfile representation gaps.
- **GitHub metadata and maintenance freshness**: archived/disabled status, inactivity, release activity, checksum evidence, CI status, branch protection, dependency update automation, and issue/PR backlog signals.
- **Repository hygiene**: CODEOWNERS sensitive-area coverage, SECURITY.md vulnerability reporting and supported version quality, and toolchain version pinning.
- **Structured evidence correlation**: SBOM and provenance files are parsed into structured artifacts, with dependency coverage, digest, identity, and conflict checks.
- **Suppression support**: `.repo-trust.json` at the repository root can suppress known findings by rule ID, path, or identity key with required reasons and optional expiration.
- **API health contract**: `/health` returns product name, version, API compatibility version, and allowed web origins.

Implemented through `v0.9.5`:

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
- repository health, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, secret quick scan, Docker, Docker Compose, Kubernetes, and Terraform analyzers,
- expanded repository documentation quality checks,
- expanded GitHub Actions release, artifact, and advanced hardening checks,
- GitLab CI security checks,
- expanded Docker cache and package-layering checks,
- Docker Compose and Kubernetes manifest checks,
- Azure Pipelines, CircleCI, and Terraform infrastructure analyzers,
- package registry configuration checks,
- structured npm, NuGet, Python, Maven, Gradle (including version catalogs), Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++ dependency inventory artifacts,
- lockfile coverage checks across supported package ecosystems,
- direct NuGet `PackageReference` parsing, including basic Central Package Management version resolution,
- `package.json` dependency section parsing for production, development, optional, and peer dependencies,
- conservative Python dependency parsing for `requirements.txt`, `pyproject.toml`, and `Pipfile`,
- Java dependency parsing for Maven `pom.xml`, Gradle `build.gradle`, `build.gradle.kts`, and `libs.versions.toml`,
- Spring Boot Actuator exposure checks from static application configuration,
- Go, Rust/Cargo, PHP/Composer, Ruby/Bundler, Dart/Flutter, Elixir/Hex, SwiftPM, and C/C++ package manager parsing,
- static dependency hygiene findings for unpinned/ranged and prerelease versions,
- npm install-time script findings for manual review,
- SBOM and provenance evidence validation, correlation, and completeness checks,
- multi-language public API extractors for TypeScript, Python, Java, Go, and Rust,
- import graph analysis, framework route detection, and deserialization/command execution heuristics,
- refactored analyzer files split into focused helpers for maintainability,
- NuGet package source recording from `NuGet.config` without network access,
- static package-origin findings for direct remote npm dependencies, local npm dependencies, insecure NuGet sources, and local NuGet sources,
- Markdown dependency inventory summaries,
- typed trust profiles recorded in reports,
- stable finding fingerprints for report output,
- CI gate options for score and severity thresholds,
- SQLite-backed package metadata caching and local OSV advisory indexing with conservative online fallback,
- dependency freshness, vulnerability, license, package-origin, and dependency-confusion review findings,
- scan progress DTOs for API/worker/frontend polling,
- built-in trust policies and profile-aware scoring,
- release evidence checks for checksums, SBOM/provenance, changelog/package version alignment, and release workflows,
- SBOM and provenance evidence import as informational release evidence,
- coverage import for Cobertura XML and lcov in deep scans,
- critical code heuristics for auth, authorization, payments, data access, file operations, network calls, cryptography, secrets, large files, and broad exception handling,
- measured low coverage and unknown coverage correlation for critical code,
- .NET public API surface extraction and baseline diff review,
- scan snapshot, trust diff, repository comparison, scheduled scan, and regression alert models,
- CLI `diff` command for comparing two JSON scan reports,
- fixture-based analyzer tests,
- public rule, architecture, API/worker, security, web UI, and contributor documentation.

The scanner does not execute repository code by default. Scan history persistence, hosted monitoring, and notification providers are planned future work; dependency intelligence is persisted locally in SQLite.

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
  -d "{\"target\":\"https://github.com/owner/repo\",\"depth\":\"standard\",\"trustProfile\":\"production\"}"

curl http://localhost:5000/api/scans/{scanId}
curl http://localhost:5000/api/scans/{scanId}/progress
curl http://localhost:5000/api/scans/{scanId}/report?format=json
```

The API accepts absolute `https://github.com/owner/repo` targets and rejects local paths, credentialed URLs, query strings, and fragments. The CLI still supports local path scans for trusted local development. The worker host uses the same application scan lifecycle and repository scan runner as the API:

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

For profile-specific scan commands and output examples, see [docs/examples.md](docs/examples.md).

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
| `v0.7.0` | Stable public platform with documented contracts, CLI/API/worker hosts, React scan workbench, and reliable reports |
| `v0.7.2` | Java and Spring Boot dependency support, plus continued React/backend scan experience |
| `v0.7.3` | Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++ dependency inventory |
| `v0.7.4` | Workspace detection and clearer console/report drill-downs |
| `v0.7.5` | GitLab CI, Docker Compose, and Kubernetes static security checks |
| `v0.8.0` | SBOM/provenance evidence import and review hardening |
| `v0.8.1` | Azure Pipelines, CircleCI, and Terraform static security checks; package registry configuration rules; SBOM correlation; GitHub Actions advanced hardening; Gradle version catalog support |
| `v0.8.7` | Dependency resolution correctness, registry/cache outcome integrity, partial-analysis safeguards, release evidence fixes, and report completeness |
| `v1.7.x` | Multi-language public API extraction, import graph analysis, framework route detection, deserialization/command execution heuristics, deeper code intelligence and false-positive reduction |
| `v2.0.0` | Policy fact engine, trust graph correlation, suppression/waiver workflow, VEX/provenance verification, deterministic remediation patches, and plugin-ready analyzer platform |

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
- [Local dependency intelligence](docs/local-intelligence.md)
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
