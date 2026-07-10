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

## Analyzer Scheduling

The orchestrator executes independent analyzers in bounded dependency waves (two to four analyzers, based on available CPU). An analyzer that consumes an artifact does not start until its declared producer has completed. Results and artifacts are committed after each wave in deterministic analyzer order, so concurrent execution cannot expose a partial artifact or reorder report findings.

This keeps large-repository scans responsive without relaxing scan budgets, dropping checks, or changing evidence rules. Analyzer-level concurrency remains bounded separately for high-volume work such as secret content scans and advisory lookups.

## Shared Repository Snapshot

Each scan builds one lazy file index containing normalized paths, size, timestamps, extensions, and file classification. Source analyzers share a bounded, asynchronous text snapshot cache instead of reading the same source file independently. The cache is scoped to the scan and capped at 64 MiB; files still retain their existing per-analyzer size and classification limits.

For a clean Git revision, the shared scan runner can reuse an identical completed result for 30 seconds when the target, revision, depth, profile, tool version, and analyzer set all match. Dirty local worktrees are never cached. Remote reuse first resolves the public repository HEAD with a bounded `git ls-remote` call. Benchmark runs disable this result cache.

The dependency inventory analyzer follows this rule with an orchestration class and per-ecosystem collectors for npm, NuGet, Python, Java/Maven/Gradle, and Spring Boot configuration. New package ecosystems should be added as new collectors plus focused tests, not as large branches inside the orchestrator.

## Scan Modes

- `Fast`: quick static snapshot without heavy network or deep code analysis.
- `Standard`: dependency, vulnerability, license, package metadata, workflow, and release checks.
- `Deep`: coverage, code criticality, public API, history, and comparison checks.

`v1.0.0` supports static-only local/API/worker scanning with dependency inventory across the documented package ecosystems and Spring Boot configuration signals.

## Application Scan Lifecycle

`RepoTrustDoctor.Application` owns scan lifecycle behavior:

- `ScanRequestValidator` normalizes target, depth, and trust profile values,
- `ScanCoordinator` creates scan IDs, stores queued state, and enqueues work,
- `IScanStore` tracks status, progress, result, failure, and cancellation state,
- `IScanJobQueue` decouples API requests from worker execution,
- `ScanJobProcessor` runs the shared repository scan runner and records completed or failed scans.

`RepoTrustDoctor.Infrastructure.Scanning` owns the default analyzer pipeline and repository workspace preparation. This prevents CLI, API, and worker hosts from each composing analyzer lists independently.

## Local Intelligence

Dependency intelligence is persisted in a shared SQLite database. Registry metadata for previously seen NuGet, npm, PyPI, and Maven packages is cached by exact requested version. OSV ecosystem archives are indexed by ecosystem and normalized package name so vulnerability candidates can be found locally before version matching.

The scanner uses online registry or OSV requests only for cache misses, expired registry entries, ecosystems that are not ready, or OSV range types that cannot be evaluated conservatively. The optional hosted updater is disabled by default and can be enabled in one production API or worker instance. See [Local Dependency Intelligence](local-intelligence.md).

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

The scan orchestrator enforces analyzer `ExecutionSafety` before execution. The default hosted path allows static analyzers and safe registry/advisory lookups; analyzers that would execute trusted tools or repository code are skipped and recorded as incomplete modules. Downstream analyzers are skipped when a required producer analyzer failed, timed out, was cancelled, or was skipped, so reports do not turn missing prerequisite evidence into a clean result.

Repository traversal uses a shared file-system helper that skips ignored heavy directories and reparse-point entries. This prevents symlinks or junctions inside an untrusted repository from expanding analysis into files outside the prepared workspace.

Report writers also treat repository-derived text as untrusted presentation data. Markdown output escapes inline finding and evidence fields, and unexpected analyzer exceptions are converted to generic module failure messages before they reach scan progress or reports.

## Scan Progress Contracts

`RepoTrustDoctor.Contracts` exposes polling-friendly scan progress DTOs for future API and worker surfaces. The lifecycle states are:

```text
Queued -> PreparingRepository -> RunningFastModules -> RunningStaticAnalyzers -> RunningDependencyAnalyzers -> RunningSecurityAnalyzers -> Scoring -> Reporting -> Completed
```

Failure and cancellation are represented with `Failed` and `Cancelled`. Module progress uses the existing domain `ModuleStatus` values so API and worker implementations can report completed, warning, failed, timed-out, skipped, or cancelled modules consistently.

The API host exposes these contracts directly through `/api/scans/{scanId}` and `/api/scans/{scanId}/progress`. The worker host consumes the same queued job model.
