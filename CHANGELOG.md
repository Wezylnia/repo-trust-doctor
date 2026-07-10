# Changelog

All notable published changes to Repository Trust Doctor are documented here. Git tags are the source of truth for released versions.

## v1.0.0 - 2026-07-10

The first stable public release turns the project into an installable, local-first repository adoption workbench with stable CLI, API, report, analyzer, and policy contracts.

### Added

- Self-contained CLI release archives for Windows, Linux x64/ARM64, and macOS x64/ARM64, plus a `RepoTrustDoctor.Tool` package.
- Tag-driven GitHub release automation with SHA-256 checksums and version validation.
- End-to-end HTTP contract tests covering API health, scan lifecycle, progress, cancellation, modules, findings, and JSON, Markdown, and SARIF exports.
- CLI benchmark output for median, P95, min/max, and slowest analyzer timings.
- React demo report, live scan progress, prioritized next steps, grouped finding filters, collapsible technical details, and desktop/mobile visual regression tests.

### Changed

- Independent analyzers run in bounded dependency-safe waves while preserving deterministic finding and artifact order.
- Source analyzers share a lazy enriched file index and a 64 MiB bounded per-scan text cache.
- Identical scans of the same clean Git revision can reuse a completed result for 30 seconds; dirty worktrees and benchmark runs bypass this cache.
- The report workspace uses a compact three-column decision band followed by full-width scores, coverage, technical details, and findings.
- Product metadata, documentation, SDK selection, package metadata, and release history are aligned on `1.0.0`.

### Validation

- Full .NET unit and analyzer suite.
- React unit tests, production build, and Playwright desktop/mobile layout snapshots.
- Large-repository corpus review with report diffs to detect score, decision, finding, or coverage regressions.
- FastAPI deep-scan median reduced from the original 9.37 seconds to 1.69 seconds in the recorded local benchmark, with no report finding changes.

### Scope

- Default scans remain static-only and do not execute repository code.
- The API and worker use process-local scan state and are intended for local or single-process use. Hosted multi-tenant operation, private-repository credential intake, durable report history, and shared queues remain outside the v1.0 scope.

## v0.9.5 - 2026-06-24

- Added dependency consistency, GitHub maintenance metadata, repository hygiene, structured evidence correlation, policy facts, and repository suppressions.
- Added API health compatibility metadata and improved the local React workbench.

## v0.9.0 - 2026-06-16

- Added trust snapshots, report diffing, repository comparison, and monitoring contracts.

## v0.8.7 - 2026-06-15

- Hardened dependency resolution, cache outcome handling, report completeness, evidence comparison, and partial-analysis safeguards.

## v0.8.6 - 2026-06-14

- Reduced dependency and code-analysis false positives and strengthened conservative fallback behavior.

## v0.8.5 - 2026-06-12

- Expanded code intelligence and analyzer correctness coverage.

## v0.8.3 - 2026-06-12

- Added multi-language public API extraction, static import graphs, framework route detection, and security-sensitive code heuristics.

## v0.7.0 - 2026-06-10

- Added release evidence, checksum, SBOM/provenance, and supply-chain review capabilities.

## v0.6.0 - 2026-06-10

- Added profile-aware scoring, policies, blocking risks, and shared CLI/API/worker scan lifecycle services.

## v0.5.0 - 2026-06-10

- Added SARIF reporting and progressive scan contracts.

## v0.4.1 - 2026-06-10

- Corrected dependency intelligence and report behavior after the v0.4 release.

## v0.4.0 - 2026-06-05

- Added safe package metadata, vulnerability, license, freshness, origin, and dependency-confusion intelligence.

## v0.3.0 - 2026-06-05

- Added structured dependency inventory and lockfile coverage.

## v0.2.0 - 2026-06-03

- Expanded repository, workflow, secret, Docker, and reporting analyzers.

## v0.1.5-alpha - 2026-06-03

- Stabilized the early analyzer and reporting foundation.

## v0.1.1-alpha - 2026-06-03

- Corrected initial CLI and analyzer behavior.

## v0.1.0-alpha - 2026-05-31

- Introduced the modular static repository scanner, finding model, scoring, CLI, reports, and CI gates.
