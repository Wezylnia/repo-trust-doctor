# Repository Trust Doctor

[![CI](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/Wezylnia/repo-trust-doctor?include_prereleases)](https://github.com/Wezylnia/repo-trust-doctor/releases)
[![Good First Issues](https://img.shields.io/github/issues/Wezylnia/repo-trust-doctor/good%20first%20issue)](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
[![Help Wanted](https://img.shields.io/github/issues/Wezylnia/repo-trust-doctor/help%20wanted)](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22)
[![License](https://img.shields.io/github/license/Wezylnia/repo-trust-doctor)](LICENSE)

Repository Trust Doctor is a modular repository analysis platform for deciding whether an open-source repository is healthy, maintainable, and trustworthy enough to use, contribute to, or depend on.

The project is intentionally evidence-based: analyzers produce findings with rule IDs, severity, confidence, evidence, and recommendations. Scoring and policy evaluation interpret those findings without hiding serious risks behind an average score.

## Current Status

This repository is at the `v0.1.5-alpha` pre-release milestone. It is an early CLI-first static scanner intended for local experimentation, repository hardening, and analyzer development.

Implemented in this alpha:

- a clean .NET solution structure,
- pure domain models,
- analyzer abstractions,
- static-only scan orchestration,
- console, JSON, and Markdown report output,
- a CLI-first workflow,
- repository health, GitHub Actions, secret quick scan, Docker, and dependency lockfile analyzers,
- npm, NuGet, and Python lockfile coverage checks,
- typed trust profiles recorded in reports,
- stable finding fingerprints for report output,
- fixture-based analyzer tests,
- public rule, architecture, security, and contributor documentation.

The scanner does not execute repository code by default. Package metadata lookup, vulnerability lookup, license analysis, SARIF output, API/worker hosting, persistence, and web UI are planned future work.

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

## Contributing

Contributor help is very welcome. The project has a set of scoped `v0.3` dependency inventory and reporting issues ready for external contributors:

- [good first issue](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
- [help wanted](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22)
- [contributor-ready](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3Acontributor-ready)
- [v0.3 dependency workstream](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3Aphase%3Av0.3)

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, safety rules, validation commands, and pull request expectations. Use [Discussions](https://github.com/Wezylnia/repo-trust-doctor/discussions) for questions or help choosing an issue.

## CLI

The CLI supports local path scans and shallow cloning for public HTTP(S) Git repository URLs:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan .
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan https://github.com/owner/repo
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md --force
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile enterprise
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --fail-under 75
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --fail-on-severity High
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- --version
```

Supported trust profiles are `Personal`, `ProductionDependency`, `EnterpriseDependency`, `CiCdTool`, `SecuritySensitiveDependency`, and `ContainerDependency`. The CLI also accepts common aliases such as `production`, `enterprise`, `ci-cd`, `security`, and `container`.

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
repo-trust-doctor scan . --format json --output report.json
```

## Architecture

The architecture separates detection from interpretation:

- `src/Apps` contains executable entry points such as the CLI.
- `src/Core` contains domain, application, contracts, and shared primitives.
- `src/Engine` contains analyzer abstractions, execution, orchestration, scoring, policies, and reporting.
- `src/Analyzers` contains independent analyzer modules.
- `src/Infrastructure` will contain Git, GitHub, package registry, persistence, security feed, caching, and background job integrations.
- `src/Infrastructure/RepoTrustDoctor.Infrastructure.Git` currently prepares local workspaces and shallow-clones public HTTP(S) Git URLs.
- `tests` contains unit, analyzer, integration, and fixture-based tests.

Read the public architecture overview in [docs/architecture.md](docs/architecture.md).

## Roadmap

The roadmap grows the platform gradually:

- `v0.1`: foundation and first local static scan,
- `v0.2`: static analyzer expansion,
- `v0.3`: dependency inventory,
- `v0.4`: vulnerability, license, and package origin intelligence,
- `v0.5`: API, worker, and progressive scan platform,
- `v0.6`: trust profiles and policies,
- `v0.7`: release and supply-chain evidence,
- `v0.8`: deep code intelligence,
- `v0.9`: history, comparison, and monitoring,
- `v1.0`: stable public release.

See [docs/roadmap.md](docs/roadmap.md) for milestone details.

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
- [Roadmap](docs/roadmap.md)
- [Development guide](docs/development.md)
- [CI usage](docs/ci-usage.md)
- [Analyzer authoring guide](docs/analyzer-authoring.md)
- [Report format](docs/report-format.md)
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
