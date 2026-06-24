# Changelog

All notable changes to Repository Trust Doctor are documented here.

## Unreleased (v1.0.5)

This release adds dependency consistency checks, GitHub metadata and maintenance
freshness analysis, repository hygiene improvements, structured evidence
correlation, policy fact evaluation, repository suppression support, and
API/Web usability polish. Version metadata and documentation are aligned
across the product.

### Added

- **Dependency Consistency Analyzer**: workspace-wide checks for major-version
  drift (TRUST-DEP052), package source-kind drift (TRUST-DEP053), and lockfile
  representation gaps (TRUST-DEP054). The analyzer consumes the dependency
  inventory artifact and emits a structured consistency artifact.
- **GitHub Metadata Analyzer**: repository maintenance freshness signals
  (TRUST-GHM001 through TRUST-GHM008) covering archived/disabled status,
  inactivity, release activity, checksum evidence, CI status, branch
  protection, dependency update automation, and open issue/PR backlog.
  Popularity metrics (stars, forks, watchers) are context-only and never
  produce findings.
- **Repository Hygiene Checks**: CODEOWNERS sensitive-area coverage
  (TRUST-REP020), SECURITY.md vulnerability reporting and supported version
  quality (TRUST-REP021, TRUST-REP022), and toolchain version pinning
  (TRUST-REP023) across Node.js, .NET, Rust, Python, and Ruby ecosystems.

## v0.8.7 - 2026-06-15

This bugfix release completes the current correctness review with stronger
dependency resolution, safer evidence comparison, clearer partial-analysis
reporting, and lower false-positive risk.

### Fixed

- Distinguished confirmed package-not-found responses from registry timeouts,
  transport failures, blocked requests, oversized responses, and invalid
  payloads.
- Restricted negative metadata caching to confirmed not-found responses and
  prevented stale negative entries from hiding registry outages.
- Added SQLite migration support for typed registry lookup status while
  preserving legacy positive cache entries and refreshing untrusted legacy
  null entries.
- Bound npm and PyPI metadata claims to the requested dependency version and
  corrected semantic NuGet latest-version ordering.
- Corrected mixed-license classification and stabilized finding identities
  across line movement, duplicate findings, reports, history, and policy links.
- Resolved exact dependency versions from Python, pnpm, Yarn, Cargo workspace,
  and Gradle version-catalog evidence without guessing ambiguous versions.
- Normalized npm aliases to their real registry package identity.
- Narrowed Maven and Gradle managed-version suppression to verified matching
  coordinates.
- Corrected workspace member discovery for npm/Yarn object declarations, Cargo
  globs and exclusions, and single-line Go workspace directives.
- Separated detached signatures from checksum evidence, ignored workflow
  comments, and made Python release-version extraction section-aware.
- Corrected monorepo release-note matching for package-local and explicitly
  shared release models.
- Prevented partial public API scans from reporting unobserved symbols as
  removed and added a bounded 4 MiB baseline reader.
- Removed false Go and C# import graph edges and deduplicated repeated
  source-target imports.
- Preserved every SARIF evidence location, deterministic maximum rule severity,
  valid rule documentation links, and Markdown module warnings/failures.

### Changed

- Added explicit metadata lookup metrics for attempted, reliable, not-found,
  failed, invalid, blocked, stale-cache, cache-hit, and network outcomes.
- Split package metadata analysis and private-key example classification into
  focused helpers; no production C# source file exceeds 500 lines.

## v0.8.3 - 2026-06-12

This bugfix release hardens the v1.7 codebase analysis engine and reduces false positives across multiple analyzers.

### Changed

- Reduced code criticality scan noise and false positives by ignoring comments, vocabulary tokens, and bounded exception handlers.
- Fixed public API baseline to avoid flagging intentional local API route endpoints.
- Hardened release evidence file reads and scan state preservation on cancel.
- Decoded compressed package registry responses correctly.
- Matched npm scope registries by package scope.
- Ignored generated release artifact roots and self-scan hygiene findings.
- Removed coverage findings in projects without coverage reports.
- Reduced dependency metadata false positives.
- Refactored large analyzer files into focused helpers (GitHub Actions, dependency inventory, package origin, CLI diff, routes).
- Updated test framework packages and pinned web manifest versions.

## v0.8.2 - 2026-06-11

This development milestone adds language-specific API extractors, static import graphs, framework route detection, and enhanced security heuristics.

### Added

- **Multi-language API extractors**: TypeScript, Python, Java, Go, and Rust public API extractors in `PublicApiAnalyzer`.
- **Static Import Graph**: Adjacency-based file dependency analysis (TRUST-CODE010) and low-coverage central file correlation (TRUST-CODE011).
- **Framework Route Detection**: Detects HTTP endpoints in ASP.NET, Express.js, Flask, Django, Spring Boot, Go (Gin/Echo), and Rust (Actix/Axum), and reports endpoints without authentication annotations (TRUST-CODE012) or framework routes (TRUST-CODE013).
- **Enhanced Heuristics**: Added deserialization API usage detection in critical code (TRUST-CODE014) and command execution API usage detection (TRUST-CODE015).

### Changed

- Improved path matching in `CoverageImportAnalyzer` and `CoverageCriticalityAnalyzer` to support monorepos with relative/absolute suffix and basename matching.

## v0.8.1 - 2026-06-11

This development milestone hardens v1.5 analyzers and adds CI/CD, infrastructure, and evidence coverage.

### Added

- **GitLab CI**: service Docker-in-Docker detection (TRUST-GLCI005) and broad cache path checks (TRUST-GLCI006).
- **Docker Compose**: Docker socket mount detection with Critical severity (TRUST-COMP006) and .env file loading checks (TRUST-COMP007).
- **Kubernetes**: hostPath volume detection (TRUST-K8S006), broad capability addition checks (TRUST-K8S007), and privilege escalation detection (TRUST-K8S008).
- **Evidence Import**: SBOM parseability validation (TRUST-EVI004), empty SBOM detection (TRUST-EVI005), and provenance parseability checks (TRUST-EVI006).
- **Gradle**: version catalog (`libs.versions.toml`) parsing with dynamic version rules for dependencies (TRUST-DEP050) and plugins (TRUST-DEP051).

### Changed

- **Secrets**: generic API key detection now skips variable references (`${...}`, `${{ ... }}`, `%...%`), example tokens, and values without uppercase/lowercase/digit mix. Requires at least 20 alphanumeric characters for generic key findings.

### Documentation

- New rule docs: `docs/rules/gitlab-ci.md`, `docs/rules/kubernetes.md`.
- Web report explanations for all new hardening rules.
- Rule catalog links updated.

## v0.8.0 - 2026-06-11

This development milestone adds imported evidence signals and hardens the v1.2-v1.5 analyzer set after review.

### Added

- SBOM and provenance/attestation evidence detection as informational release findings.
- Negative regression tests for Kubernetes non-workload YAML, GitHub Actions secret expressions, read-only workflow permissions, Cargo exact requirements, Ruby missing/prerelease constraints, monorepo lockfile placement, and string-form vcpkg dependencies.

### Changed

- Product version is now `0.8.0`.
- Web app version is now `0.8.0`.
- Workspace and imported evidence signals are informational and do not reduce trust scores.
- Kubernetes hardening checks now require Kubernetes workload content with container specs instead of relying on filename heuristics.
- GitHub Actions hardcoded-secret checks ignore `${{ secrets.* }}` expressions and read-only permission declarations.
- Cargo exact-version detection now follows Cargo requirement semantics: `=1.2.3` is exact, while bare `1.2.3` is still a compatible requirement.
- Lockfile checks for Ruby, Dart/Pub, Elixir/Hex, and SwiftPM now require a sibling lockfile for each manifest.
- Dependency inventory tests and CLI console rendering were split into smaller, maintainable files.

## v0.7.5 - 2026-06-11

This development milestone expands static CI/CD and infrastructure coverage.

### Added

- GitLab CI analyzer for remote includes, CI variable shell interpolation, `latest` image tags, and deprecated `only`/`except`.
- Docker Compose analyzer for privileged services, host networking, host mounts, broad port bindings, and secret-like environment values.
- Kubernetes manifest analyzer for privileged containers, host namespace sharing, missing non-root/read-only filesystem hardening, and committed Secret manifests.
- React report drill-down support for the new analyzer families.

## v0.7.4 - 2026-06-11

This development milestone adds workspace awareness and console/report ergonomics.

### Added

- Workspace detection for npm, Cargo, and Go workspaces.
- Console category score bars, dependency summary output, and top recommended actions.
- SARIF help URI support and richer report rule explanations.

## v0.7.3 - 2026-06-11

This release adds dependency ecosystem support for Go, Rust/Cargo, PHP/Composer, Ruby/Bundler, Dart/Flutter, Elixir/Hex, Swift Package Manager, and C/C++ package managers.

### Added

- **Go**: `go.mod` parsing, `go.sum` detection, replace directive review, pseudo-version detection (TRUST-DEP022-DEP025).
- **Rust/Cargo**: `Cargo.toml` parsing across dependency sections, `Cargo.lock` detection, Git/path source detection, version pinning and prerelease checks (TRUST-DEP026-DEP030).
- **PHP/Composer**: `composer.json` parsing for require/require-dev, `composer.lock` detection, version constraint analysis (TRUST-DEP031-DEP033).
- **Ruby/Bundler**: `Gemfile` and `.gemspec` parsing, `Gemfile.lock` detection, version constraint and Git/path source detection (TRUST-DEP034-DEP036).
- **Dart/Flutter**: `pubspec.yaml` parsing, `pubspec.lock` detection, version constraint analysis (TRUST-DEP037-DEP038).
- **Elixir/Hex**: `mix.exs` parsing, `mix.lock` detection, version constraint and non-Hex source detection (TRUST-DEP040-DEP042).
- **Swift/SPM**: `Package.swift` parsing, `Package.resolved` detection, branch-based dependency detection (TRUST-DEP043-DEP044).
- **C/C++**: Conan (`conanfile.txt`/`conanfile.py`), vcpkg (`vcpkg.json`), and CMake (`find_package`/`FetchContent`) detection (TRUST-DEP046-DEP048).
- **Secrets**: Azure connection strings, GCP service account keys, JWT tokens, npm/PyPI registry tokens, and generic API key detection (TRUST-SECRET008-SECRET012). Placeholder value suppression for generic API key rule.
- **GitHub Actions**: GITHUB_TOKEN scope restriction, hardcoded secrets in step env, and matrix injection detection (TRUST-GHA011, GHA013-GHA014).
- **Docker**: ADD vs COPY preference, sudo usage, and broad EXPOSE port range detection (TRUST-DOCKER009-DOCKER011).
- **CLI**: Category scores with visual bars in console output.
- Expanded sensitive file detection (`.git-credentials`, `.netrc`, `.ppk`, `.p12`, `.pfx`).

### Changed

- Product version is now `0.7.3`.
- Rule count: 110 → 133 across 12 ecosystems.

## v0.7.2 - 2026-06-11

This release adds Java and Spring Boot dependency analysis.

### Added

- Maven ecosystem support in dependency inventory, package metadata lookup, and OSV vulnerability queries.
- Static Maven `pom.xml` parsing for direct dependency coordinates and Maven property-resolved versions.
- Static Gradle `build.gradle` and `build.gradle.kts` parsing for common dependency declarations.
- Java dependency rules for missing lock evidence, dynamic versions, SNAPSHOT/prerelease versions, missing Gradle wrapper files, and broad Spring Boot Actuator exposure.
- Analyzer and infrastructure tests covering Maven, Gradle, Spring Boot configuration, Maven Central metadata, and Maven OSV routing.

### Changed

- Product version is now `0.7.2`.
- Web app version is now `0.7.2`.

## v0.7.1 - 2026-06-11

This release improves the React scan and report experience.

### Changed

- Product version is now `0.7.1`.
- Web app version is now `0.7.1`.
- Scan depth choices now use plain labels such as `Fast scan`, `Standard scan`, and `Deep scan`.
- Trust profile choices are reduced to three clear options: personal, production, and enterprise/security-sensitive.
- Legacy CI/CD and container profile inputs now map to production while the underlying workflow and container analyzers remain part of normal scans.
- Added a main scan introduction, a clearer right-side profile guide, area score cards, report display labels, and richer finding explanations.

## v0.7.0 - 2026-06-11

This release corrects the React product flow so users scan a GitHub repository directly instead of importing or pasting raw JSON.

### Added

- GitHub-locked repository input with a fixed `github.com/` prefix.
- Paste normalization for full GitHub URLs such as `https://github.com/owner/repo`.
- Overall 100-point score emphasis at the top of the report.
- Score color bands: `90+` dark green, `80-89` green, `60-79` yellow, below `60` red.
- Unit tests for GitHub repository normalization and score tone mapping.

### Changed

- Product version is now `0.7.0`.
- Web app version is now `0.7.0`.
- Removed the Saved report/import UI from the React app.
- Removed sample report loading from the React app.
- Hid the local backend URL from the user-facing scan form; `localhost:5000` is now treated as the local scan service, not a scan target.
- README, roadmap, and web UI docs now describe the GitHub-first React scan flow.

### Security

- The React UI no longer accepts raw JSON report input.
- The React UI no longer exposes arbitrary local path scanning.
- Default backend scans remain static-only.

## v1.0.5 - 2026-06-11

This release improves the React experience from a secondary JSON viewer into a local backend-backed trust workbench.

### Added

- React scan workspace that starts scans through the local API backend and opens completed reports directly.
- Saved report fallback for opening or pasting existing JSON scan artifacts.
- Report overview panels for final decision reasons and category scores.
- Web unit tests for report selectors and API scan helper behavior.
- Local web CORS policy for the API host, configurable through `RepoTrustDoctor:WebOrigins`.

### Changed

- Product version is now `0.6.5`.
- Web app version is now `0.6.5`.
- The web app opens on the scan flow by default instead of asking users to import JSON first.
- The UI language now treats saved JSON as an artifact fallback, not the primary report flow.
- The visual design is flatter, denser, and more operations-focused.
- README, roadmap, and web UI docs now describe the React/backend scan direction and `v1.1.0` follow-up plan.

### Security

- Default scans remain static-only.
- The React app talks to the local API backend; it does not introduce public hosted scan intake.
- API CORS is limited to configured local web origins by default.

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

- Product version is now `0.6.0`.
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
