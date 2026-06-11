# Architecture

Repository Trust Doctor is designed as a modular analysis platform rather than a single scanner. Analyzer modules produce evidence, the engine orchestrates execution, scoring interprets findings, policies decide acceptability, and applications expose the result.

## Solution Areas

```text
src/
  Apps/
    RepoTrustDoctor.Cli/
    RepoTrustDoctor.Api/
    RepoTrustDoctor.Worker/
  Core/
  Engine/
  Analyzers/
  Infrastructure/
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
| `Apps` | Executable entry points such as CLI, API, worker, and local report viewer |
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
Apps -> Infrastructure.Scanning
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

The dependency inventory analyzer follows this rule with an orchestration class and per-ecosystem collectors for npm, NuGet, Python, Java/Maven/Gradle, and Spring Boot configuration. New package ecosystems should be added as new collectors plus focused tests, not as large branches inside the orchestrator.

## Scan Modes

- `Fast`: quick static snapshot without heavy network or deep code analysis.
- `Standard`: dependency, vulnerability, license, package metadata, workflow, and release checks.
- `Deep`: coverage, code criticality, public API, history, and comparison checks.

`v1.1` ships static-only local/API/worker scanning with dependency inventory support for npm, NuGet, Python, Maven, Gradle, and Spring Boot configuration signals.

## Application Scan Lifecycle

`RepoTrustDoctor.Application` owns scan lifecycle behavior:

- `ScanRequestValidator` normalizes target, depth, and trust profile values,
- `ScanCoordinator` creates scan IDs, stores queued state, and enqueues work,
- `IScanStore` tracks status, progress, result, failure, and cancellation state,
- `IScanJobQueue` decouples API requests from worker execution,
- `ScanJobProcessor` runs the shared repository scan runner and records completed or failed scans.

`RepoTrustDoctor.Infrastructure.Scanning` owns the default analyzer pipeline and repository workspace preparation. This prevents CLI, API, and worker hosts from each composing analyzer lists independently.

## Repository Workspace Preparation

`RepoTrustDoctor.Infrastructure.Git` prepares the repository workspace before analysis:

- local paths are scanned in place,
- HTTP(S) repository URLs are cloned into a temporary directory with `git clone --depth 1 --no-tags`,
- repository URLs containing credentials or fragments are rejected,
- clone disables `file` and `ext` protocols and does not recurse into submodules,
- temporary clone directories are deleted after the scan,
- repository code is not executed during preparation.

Static analyzers may skip local-only or generated directories such as `.git`, `bin`, `obj`, `node_modules`, `.repo-trust`, and this repository's ignored `private-docs` source notes when scanning for secret patterns.
Static analyzers also apply bounded text reads so unusually large files are not read wholesale during quick static checks.

## Security Baseline

Repository code is untrusted input. Hosted scans should only allow static file reads and safe network metadata lookups unless execution is explicitly enabled in a sandboxed mode.

## Scan Progress Contracts

`RepoTrustDoctor.Contracts` exposes polling-friendly scan progress DTOs for future API and worker surfaces. The lifecycle states are:

```text
Queued -> PreparingRepository -> RunningFastModules -> RunningStaticAnalyzers -> RunningDependencyAnalyzers -> RunningSecurityAnalyzers -> Scoring -> Reporting -> Completed
```

Failure and cancellation are represented with `Failed` and `Cancelled`. Module progress uses the existing domain `ModuleStatus` values so API and worker implementations can report completed, warning, failed, timed-out, skipped, or cancelled modules consistently.

The API host exposes these contracts directly through `/api/scans/{scanId}` and `/api/scans/{scanId}/progress`. The worker host consumes the same queued job model.
