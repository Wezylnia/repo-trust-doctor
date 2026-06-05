# Changelog

All notable changes to Repository Trust Doctor are documented here.

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
