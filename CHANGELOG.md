# Changelog

All notable changes to Repository Trust Doctor are documented here.

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