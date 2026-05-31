# Repository Trust Doctor

Repository Trust Doctor is a modular repository analysis platform for deciding whether an open-source repository is healthy, maintainable, and trustworthy enough to use, contribute to, or depend on.

The project is intentionally evidence-based: analyzers produce findings with rule IDs, severity, confidence, evidence, and recommendations. Scoring and policy evaluation interpret those findings without hiding serious risks behind an average score.

## Current Status

This repository is at the start of the `v0.1` foundation milestone.

The first milestone focuses on:

- a clean .NET solution structure,
- pure domain models,
- analyzer abstractions,
- static-only scan orchestration,
- JSON and Markdown report output,
- a CLI-first workflow,
- fixture-based analyzer tests.

The first usable scanner will not execute repository code by default.

## CLI

The current skeleton supports local path scans and shallow cloning for public HTTP(S) Git repository URLs:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan .
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan https://github.com/owner/repo
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md --force
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile enterprise
```

Supported trust profiles are `Personal`, `ProductionDependency`, `EnterpriseDependency`, `CiCdTool`, `SecuritySensitiveDependency`, and `ContainerDependency`. The CLI also accepts common aliases such as `production`, `enterprise`, `ci-cd`, `security`, and `container`.

### CLI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed and no blocking avoid decision |
| `1`  | CLI usage error |
| `2`  | Input/output error (e.g. refusing to overwrite an existing report) |
| `3`  | Scan completed with `AvoidAsProductionDependency` decision |

Planned packaged CLI commands:

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
- [Analyzer authoring guide](docs/analyzer-authoring.md)
- [Report format](docs/report-format.md)
- [Trust profiles](docs/policies/trust-profiles.md)
- [Rule catalog](docs/rules/README.md)

## Repository Governance

The public repository uses protected `main`, required pull request review for non-admin contributors, required CI status checks, CodeQL, OSSF Scorecard, Dependabot, and Copilot review instructions. Repository admins can bypass branch protection for urgent maintenance.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.

## Disclaimer

repo-trust-doctor provides heuristic, evidence-based repository analysis. It does not certify that a repository, dependency, workflow, package, or release is secure, safe, compliant, or free from vulnerabilities.

Reports may contain false positives or false negatives. The tool is intended to support decision-making and does not replace manual review, legal review, security testing, or professional audit.
