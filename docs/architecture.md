# Architecture

Repository Trust Doctor is designed as a modular analysis platform rather than a single scanner. Analyzer modules produce evidence, the engine orchestrates execution, scoring interprets findings, policies decide acceptability, and applications expose the result.

## Solution Areas

```text
src/
  Apps/
  Core/
  Engine/
  Analyzers/
  Infrastructure/
  Presentation/
tests/
  Unit/
  Analyzers/
  Integration/
  Fixtures/
docs/
samples/
tools/
```

## Layer Responsibilities

| Area | Responsibility |
| --- | --- |
| `Apps` | Executable entry points such as CLI, API, and worker |
| `Core` | Domain model, use cases, contracts, and tiny shared primitives |
| `Engine` | Analyzer contracts, execution, orchestration, scoring, policies, and reporting |
| `Analyzers` | Independent analysis modules grouped by domain |
| `Infrastructure` | External systems such as Git, GitHub, registries, feeds, caches, and persistence |
| `tests` | Unit, analyzer, integration, and fixture tests |

## Dependency Direction

Domain stays pure and does not depend on apps, infrastructure, UI, or analyzer implementations.

Allowed direction:

```text
Apps -> Application -> Domain
Apps -> Engine abstractions/orchestration
Engine -> Domain + Analysis.Abstractions
Analyzers -> Analysis.Abstractions + Domain
Infrastructure -> abstractions + Domain
```

Forbidden direction:

```text
Domain -> Infrastructure
Domain -> API/CLI/Worker
Application -> concrete GitHub/database clients
Analyzer -> API/UI/Worker
Analyzer -> another analyzer implementation
Scoring -> Infrastructure
```

## Analyzer Rule

Analyzers detect evidence and emit structured findings. They do not calculate final scores, make profile-specific decisions, or directly call other analyzers. Reusable data flows through artifacts in the analysis context.

## Scan Modes

- `Fast`: quick static snapshot without heavy network or deep code analysis.
- `Standard`: dependency, vulnerability, license, package metadata, workflow, and release checks.
- `Deep`: coverage, code criticality, public API, history, and comparison checks.

`v0.1` starts with static-only local scanning and the foundation required for future scan modes.

## Repository Workspace Preparation

`RepoTrustDoctor.Infrastructure.Git` prepares the repository workspace before analysis:

- local paths are scanned in place,
- HTTP(S) repository URLs are cloned into a temporary directory with `git clone --depth 1 --no-tags`,
- temporary clone directories are deleted after the scan,
- repository code is not executed during preparation.

Static analyzers may skip local-only or generated directories such as `.git`, `bin`, `obj`, `node_modules`, `.repo-trust`, and this repository's ignored `private-docs` source notes when scanning for secret patterns.

## Security Baseline

Repository code is untrusted input. Hosted scans should only allow static file reads and safe network metadata lookups unless execution is explicitly enabled in a sandboxed mode.
