# Changelog

All notable changes to Repository Trust Doctor are documented here.

## v1.0.0 - 2026-06-10

This release promotes Repository Trust Doctor to a stable public platform with shared scan lifecycle services, CLI/API/worker scan hosts, centralized analyzer composition, documented API contracts, and refreshed release documentation.

### Added

- Shared application scan lifecycle services for validation, queuing, status, progress, cancellation, completion, and failure handling.
- In-memory scan store and job queue suitable for local API/worker hosting and future persistence adapters.
- Central `DefaultRepositoryScanRunner` used by CLI, API, and worker hosts.
- API host with health, start scan, list scans, scan status, scan progress, modules, findings, report export, and cancellation endpoints.
- Worker host using the same queued scan processor as the API.
- API and worker documentation with endpoint reference, current storage model, and safety notes.
- Unit tests for scan lifecycle behavior and default runner composition.

### Changed

- Product version is now `1.0.0`.
- CLI scan execution now uses the centralized repository scan runner instead of composing analyzers in the app entry point.
- README, roadmap, architecture, development, report format, ADR, release checklist, and trust profile docs now reflect the stable 1.0 platform.

### Security

- API and worker scans keep the same static-only default safety posture as CLI scans.
- Credentialed repository URLs remain rejected before workspace preparation.
- API report export uses existing JSON, Markdown, and SARIF writers instead of introducing a separate report path.
- `v1.0.0` API/worker state is in-memory and local-host oriented; durable hosted deployments should add persistence, queue, authentication, authorization, and intake controls before public exposure.

## v0.9.0 - 2026-06-10

This release adds trust history, scan snapshots, trust diff, repository comparison, scheduled scan contracts, and regression alert foundations.

### Added

- `RepoTrustDoctor.TrustHistory` engine project.
- `ScanSnapshot` model derived from existing scan reports without storing raw repository source files.
- Trust diff engine for score deltas, category deltas, new findings, resolved findings, worsened findings, improved findings, and unchanged findings.
- Repository comparison engine for sorting multiple snapshots by trust risk.
- Scheduled scan contract and regression alert detector for score drops, worsened decisions, new blocking findings, and new high-severity findings.
- CLI `diff <before.json> <after.json>` command with console, JSON, and Markdown output.
- Unit tests for snapshot creation, diff behavior, repository comparison, regression alerts, and diff option parsing.
- Trust history and diff documentation.

### Changed

- Product version is now `0.9.0`.
- README, roadmap, and report format docs now describe trust diff and history models.

### Security

- Trust diff reads local JSON reports and does not clone repositories, execute code, or contact remote services.
- Snapshots store finding metadata and primary file paths, not raw repository source files.
- Regression alerts are local model outputs and do not send notifications by default.

## v0.8.0 - 2026-06-10

This release adds deep code intelligence for imported coverage, critical source files, critical coverage gaps, and conservative .NET public API review.

### Added

- Codebase analyzer project registered in the CLI deep scan pipeline.
- Coverage import analyzer for Cobertura XML and lcov reports.
- Static critical code heuristics for auth, authorization, payments, data access, file operations, network calls, cryptography, secrets, large files, and broad exception handling.
- Critical coverage correlation that blocks on critical files with low or missing imported coverage.
- .NET public API extraction and optional baseline comparison with `.repo-trust/public-api-baseline.txt`, `docs/public-api-baseline.txt`, or `public-api-baseline.txt`.
- Rule catalog page for `TRUST-CODE001` through `TRUST-CODE009`.
- Analyzer tests covering Cobertura, lcov, unsafe XML handling, criticality signals, coverage correlation, and public API baselines.

### Changed

- Product version is now `0.8.0`.
- README, roadmap, and report format docs now describe deep code intelligence artifacts and rules.

### Security

- Deep code intelligence remains static/imported-evidence based.
- The scanner does not execute repository tests, builds, package managers, or source code to generate coverage.
- Coverage XML parsing disables DTD processing and external resource resolution.
- Public API diffs are review signals and do not claim every removed symbol is a breaking change.

## v0.7.0 - 2026-06-10

This release adds release and supply-chain evidence checks for local release artifacts, package version consistency, changelog alignment, and release workflow integrity evidence.

### Added

- Release evidence analyzer registered in the CLI standard/deep scan pipeline.
- Release rules:
  - `TRUST-REL001`: changelog does not mention detected package version.
  - `TRUST-REL002`: release artifact lacks checksum evidence.
  - `TRUST-REL003`: release artifact lacks SBOM or provenance evidence.
  - `TRUST-REL004`: package version does not match latest changelog version.
  - `TRUST-REL005`: release workflow lacks integrity evidence steps.
- Rule catalog page for release evidence rules.
- Analyzer tests for package/changelog mismatch, artifact integrity evidence, and release workflow integrity evidence.

### Changed

- Product version is now `0.7.0`.
- README and roadmap now describe release trust as the current milestone.

### Security

- Release evidence analysis is static-only.
- The analyzer does not download, execute, unpack, or verify release artifacts by default.

## v0.6.0 - 2026-06-10

This release introduces built-in trust policy presets, policy evaluation, blocking risks, and profile-aware scoring.

### Added

- Built-in `TrustPolicy` presets for all trust profiles.
- Policy fields for license handling, vulnerability severity, minimum scores, SECURITY.md requirement, unpinned action handling, release checksum expectations, and allowed registries.
- Policy evaluation results with violations, warnings, and blocking risks.
- Profile-aware scoring multipliers for personal, production, enterprise, CI/CD, security-sensitive, and container use cases.
- Blocking policy risks can override high numeric scores.

### Changed

- Product version is now `0.6.0`.
- Scoring is no longer profile-neutral.
- Trust profile documentation now describes built-in presets and policy evaluation.

### Security

- Policy evaluation interprets findings; analyzers still only produce evidence.
- Policy evaluation does not execute repository code or make legal conclusions.

## v0.5.0 - 2026-06-10

This release adds SARIF reporting and shared scan progress contracts for API, worker, and frontend-ready scan lifecycle work.

### Added

- SARIF 2.1.0 report writer with deterministic rule/result output.
- CLI support for `--format sarif` with the same output overwrite protection as JSON and Markdown.
- SARIF mapping for rule IDs, severity levels, locations, stable partial fingerprints, confidence, category, and blocking metadata.
- Polling-friendly scan lifecycle and module progress DTOs in `RepoTrustDoctor.Contracts`.
- Unit tests for SARIF output, CLI parsing, secret-safe SARIF evidence behavior, and progress DTO serialization.

### Changed

- Product version is now `0.5.0`.
- README and report format docs document SARIF output.

### Security

- SARIF output does not include raw evidence values.
- Progress DTO status messages are designed for sanitized status text and do not introduce API or hosted scan execution behavior.

## v0.4.1 - 2026-06-10

This release completes the first dependency risk intelligence layer with safe package metadata and advisory foundations. Registry and advisory access is isolated behind allowlisted lookup clients and analyzer failures remain partial-result friendly.

### Added

- Safe HTTP lookup abstraction with HTTPS, host allowlist, credential, redirect, timeout, and response-size protections.
- Common package registry metadata and vulnerability advisory models.
- NuGet, npm, and PyPI metadata clients with fixture-oriented parsers.
- OSV advisory client and parser.
- License normalization for common permissive and copyleft license families.
- Dependency risk analyzers for package freshness, known vulnerabilities, license metadata, package origin metadata, and dependency-confusion review signals.
- Analyzer and unit tests for safe lookup, parser behavior, license normalization, and dependency risk findings.

### Security

- Metadata and advisory clients do not follow package-provided repository or homepage URLs.
- Tests do not require real registry or OSV network calls.
- Dependency risk findings use cautious language and do not claim exploitability, legal conclusions, or malicious package intent.

## v0.4.0 - 2026-06-05

This release starts the risk intelligence milestone with static package-origin checks. It builds on the dependency inventory artifact without adding package downloads, registry metadata calls, vulnerability lookups, or license claims.

### Added

- Static npm package-origin findings:
  - `TRUST-DEP011`: npm dependency uses a direct remote source.
  - `TRUST-DEP012`: npm dependency uses a local file source.
- Static NuGet package-source findings:
  - `TRUST-DEP013`: NuGet package source uses insecure transport.
  - `TRUST-DEP014`: NuGet package source uses a local path.
- Dependency package source metadata for local sources and secure transport.
- Dependency inventory metrics for insecure package sources, local package sources, direct remote npm sources, and local npm sources.
- Markdown dependency inventory summary fields for package-origin risk signals.
- Analyzer fixture tests and report writer tests for package-origin risk signals.

### Changed

- Product version is now `0.4.0`.
- README, roadmap, report format docs, and dependency rule docs now describe the first static package-origin intelligence milestone.

### Security

- Package-origin checks remain static-only.
- The scanner does not contact npm, NuGet, PyPI, GitHub, OSV, package registries, or package URLs for this release.
- NuGet source URLs continue to redact embedded credentials before entering artifacts or evidence.

### Known Limitations

- Vulnerability lookup, license analysis, package metadata freshness, typosquatting detection, and dependency confusion checks are still planned future work.
- Direct remote and local source findings are heuristic review signals, not proof that a dependency is malicious.

## v0.3.0 - 2026-06-05

This release completes the first dependency inventory milestone. It turns the previous lockfile coverage checks into a reusable static dependency inventory for NuGet, npm, and Python while preserving the scanner's no-code-execution safety model.

### Added

- `DependencyInventoryArtifact` with manifest, lockfile, package, package source, and metric records.
- Dependency inventory artifacts are carried through scan results for report writers and future analyzers.
- NuGet direct `PackageReference` parsing, including nested `<Version>` nodes.
- Basic Central Package Management version resolution through `Directory.Packages.props`.
- Static NuGet findings:
  - `TRUST-DEP004`: NuGet dependency uses a floating or unpinned version.
  - `TRUST-DEP005`: NuGet dependency uses a prerelease version.
- NuGet package source recording from `NuGet.config` with credential redaction.
- npm dependency parsing for `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`.
- npm `packageManager` and `engines` metadata capture.
- Static npm findings:
  - `TRUST-DEP006`: npm dependency uses a range or unpinned version.
  - `TRUST-DEP007`: npm dependency uses a prerelease version.
  - `TRUST-DEP008`: npm install-time script requires manual review.
- Python dependency parsing for `requirements.txt`, `pyproject.toml`, and `Pipfile`.
- Static Python findings:
  - `TRUST-DEP009`: Python requirement is unpinned.
  - `TRUST-DEP010`: Python dependency uses a prerelease version.
- Markdown dependency inventory summary with counts by ecosystem.
- Markdown top recommended actions section.

### Changed

- Product version is now `0.3.0`.
- README, roadmap, report format docs, and dependency rule docs now describe the dependency inventory milestone.

### Security

- Dependency inventory remains static-only.
- The scanner does not execute package managers, repository scripts, builds, tests, Docker builds, or install hooks.
- XML parsing disables DTD processing and external resource resolution.
- NuGet source URLs redact embedded credentials before entering artifacts.

### Known Limitations

- Package registry metadata, latest-version freshness, vulnerability lookup, license analysis, package origin analysis, and dependency confusion analysis are not implemented yet.
- Dependency parsing is conservative and does not perform full MSBuild, npm, Poetry, uv, Pipenv, or Python packaging resolution.
- Reports may contain heuristic false positives or false negatives.

## v0.2.0 - 2026-06-03

This release completes the `v0.2` static analyzer expansion milestone. It improves repository documentation quality checks, GitHub Actions release/artifact review, Dockerfile hygiene checks, rule documentation, and fixture coverage while keeping scans static-only by default.

### Added

- Repository health rules:
  - `TRUST-REPO012`: README lacks quick start guidance.
  - `TRUST-REPO013`: Documentation folder is missing.
  - `TRUST-REPO014`: README contains broken-looking local link.
- Docker rules:
  - `TRUST-DOCKER007`: Dockerfile copies entire context before dependency restore.
  - `TRUST-DOCKER008`: Dockerfile separates `apt-get update` from install.
- GitHub Actions rules:
  - `TRUST-GHA009`: Release workflow may publish without test dependency.
  - `TRUST-GHA010`: Workflow uploads overly broad artifact path.
- Positive and negative analyzer fixture tests for the new rules.
- Public rule documentation for all new repository, Docker, and GitHub Actions rules.

### Changed

- Product version is now `0.2.0`.
- README and roadmap now describe `v0.2.0` as the current static analyzer expansion milestone.

### Security

- New checks remain static-only and do not execute repository code, package managers, workflows, Docker builds, or release artifacts.
- New heuristic findings use medium confidence where false positives are plausible.

### Known Limitations

- Package metadata, vulnerability, license, package origin, and dependency confusion analysis are not implemented yet.
- SARIF output is designed but not implemented yet.
- API, worker, persistence, hosted scanning, and web UI are not implemented yet.
- Trust profiles are recorded in reports, but scoring is intentionally profile-neutral until policy thresholds are implemented.
- Findings are heuristic and may include false positives or false negatives.

## v0.1.5-alpha - 2026-06-03

This alpha release improves CLI automation support for CI and release hardening while keeping the scanner static-only.

### Added

- `--fail-under <0-100>` CLI gate, returning exit code `4` when the trust score is below the configured threshold.
- `--fail-on-severity <severity>` CLI gate, returning exit code `4` when any finding is at or above the configured severity.
- Console summary metadata for tool version, scan depth, trust profile, and severity counts.
- CI usage documentation with safe static-analysis examples.

### Changed

- Product version is now `0.1.5-alpha`.
- README now documents CI gating options and the new exit code.

### Validation

- `dotnet test RepoTrustDoctor.slnx`
- `dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- --version`
- `dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --fail-under 80`

## v0.1.1-alpha - 2026-06-03

This alpha maintenance release improves release metadata consistency and CLI discoverability without expanding the analyzer scope beyond the current static-only foundation.

### Added

- Central product metadata for the tool name and version.
- CLI version command through `--version`, `-v`, and `version`.
- Release checklist documentation for maintainer validation before publishing pre-releases.

### Changed

- Reports now use the shared product version source instead of a locally hardcoded orchestrator value.
- README now documents the current alpha version and version command.
- Synthetic secret scanner test values were split in source so self-scans no longer report them as possible leaked secrets.

### Validation

- `dotnet test RepoTrustDoctor.slnx`
- `dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- --version`

## v0.1.0-alpha - 2026-05-31

This is the first public alpha release of Repository Trust Doctor. It is an early CLI-first static scanner for local repository trust analysis and analyzer development.

### Added

- .NET solution structure with separated Apps, Core, Engine, Infrastructure, and Analyzer areas.
- Domain models for scans, modules, findings, evidence, recommendations, severity, confidence, scores, decisions, and trust profiles.
- Analyzer abstraction, isolated executor, cancellation and timeout handling, and static-only orchestration.
- CLI scan command for local paths and public HTTP(S) Git repository URLs.
- Console, JSON, and Markdown report output.
- Stable SHA-256 finding fingerprints in report output.
- Repository health analyzer.
- GitHub Actions analyzer for risky permissions, unpinned actions, shell pipe execution, `pull_request_target`, checkout credential persistence, and related workflow risks.
- Secret quick scan analyzer with redaction-aware evidence for common secret-like patterns.
- Docker analyzer for basic container and Dockerfile hygiene signals.
- Dependency inventory analyzer for npm, NuGet, and Python lockfile coverage.
- Built-in `TrustProfile` enum and CLI profile aliases.
- Profile-neutral scoring tests documenting current policy behavior.
- Rule catalog documentation for implemented analyzer families.
- Architecture, report format, security review, ADR, trust profile, and analyzer authoring documentation.
- GitHub Actions CI, CodeQL, OSSF Scorecard, Dependabot, and protected branch governance.

### Security

- Default scans are static-only and do not execute repository code.
- Public HTTP(S) Git URL preparation rejects credentialed or unsafe repository URLs.
- Analyzer failures are isolated so partial reports remain useful.
- Possible secret evidence is redacted and excluded from finding fingerprint inputs.
- Workflow actions are pinned to full commit SHAs.

### Known Limitations

- Package metadata, vulnerability, license, package origin, and dependency confusion analysis are not implemented yet.
- SARIF output is designed but not implemented yet.
- API, worker, persistence, hosted scanning, and web UI are not implemented yet.
- Trust profiles are recorded in reports, but scoring is intentionally profile-neutral until policy thresholds are implemented.
- Findings are heuristic and may include false positives or false negatives.
