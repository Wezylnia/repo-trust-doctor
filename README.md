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

## Planned CLI

```text
repo-trust-doctor scan .
repo-trust-doctor scan https://github.com/owner/repo
repo-trust-doctor scan . --format json
repo-trust-doctor scan . --format markdown
```

## Architecture

The architecture separates detection from interpretation:

- `src/Apps` contains executable entry points such as the CLI.
- `src/Core` contains domain, application, contracts, and shared primitives.
- `src/Engine` contains analyzer abstractions, execution, orchestration, scoring, policies, and reporting.
- `src/Analyzers` contains independent analyzer modules.
- `src/Infrastructure` will contain Git, GitHub, package registry, persistence, security feed, caching, and background job integrations.
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

## Documentation

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Development guide](docs/development.md)
- [Analyzer authoring guide](docs/analyzer-authoring.md)
- [Report format](docs/report-format.md)

## License

This project is currently prepared for a public repository. A license file will be added before the first tagged release.
