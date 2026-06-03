# Roadmap

Repository Trust Doctor grows in layers: first the static analyzer platform, then dependency intelligence, then policy-aware risk decisions, then hosted scanning and deeper trust signals.

The roadmap is intentionally conservative. Each milestone should leave the project easier to extend, not just larger.

## Current Release

`v0.1.5-alpha` is an early CLI-first static scanner. It includes the foundation platform, first static analyzers, dependency lockfile coverage checks, typed trust profile recording, stable finding fingerprints, CI gate options, and public rule/security documentation.

Current scans are static-only by default. The tool does not execute repository code, install packages, run tests, run builds, or build containers as part of a scan.

## Milestone Summary

| Version | Theme | Main Outcome |
| --- | --- | --- |
| `v0.1.x` | Foundation alpha | Local static scans, report output, basic analyzers, CI gates |
| `v0.2.x` | Static analyzer expansion | Better repository, workflow, secret, Docker, and report quality |
| `v0.3.x` | Dependency inventory | Structured NuGet, npm, and Python dependency artifacts |
| `v0.4.x` | Risk intelligence | Vulnerability, license, package origin, typosquatting, dependency confusion |
| `v0.5.x` | API and worker foundation | Hosted scan API, worker execution, persistence, progress DTOs |
| `v0.6.x` | Policies and profiles | Built-in policies, blocking risks, profile-aware scoring |
| `v0.7.x` | Release trust | Release hygiene, artifact integrity, SBOM/provenance evidence |
| `v0.8.x` | Deep code intelligence | Coverage import, code criticality, public API risk |
| `v0.9.x` | History and comparison | Trust diff, historical trend, repository comparison, monitoring |
| `v1.0.0` | Stable public release | Stable contracts, documented reports, contributor-ready platform |

## v0.1.x: Foundation Alpha

Goal: make the project useful as a local static scanner and stable enough for analyzer contributors.

Delivered:

- modular .NET solution structure,
- pure domain model for scans, modules, findings, evidence, recommendations, scores, and decisions,
- analyzer abstraction with metadata, scan depth, dependencies, execution safety, timeout, and cancellation,
- isolated analyzer execution and partial-result behavior,
- local path scans and shallow public HTTP(S) Git URL scans,
- console, JSON, and Markdown report output,
- stable finding fingerprints,
- repository health analyzer,
- GitHub Actions analyzer,
- secret quick scan analyzer,
- Docker analyzer,
- dependency lockfile coverage analyzer,
- typed trust profiles recorded in reports,
- CI gate options: `--fail-under` and `--fail-on-severity`,
- rule catalog, architecture docs, security docs, contributor docs, and release checklist.

Remaining `v0.1.x` maintenance work may include:

- small CLI ergonomics,
- report wording improvements,
- test coverage gaps around existing behavior,
- documentation polish,
- minor false-positive cleanup for existing analyzer rules.

Out of scope:

- package registry lookups,
- vulnerability lookup,
- license analysis,
- hosted file upload scanning,
- API/worker persistence,
- web UI,
- execution-based analysis.

Success criteria:

- local scans complete reliably,
- reports are deterministic enough for CI artifacts,
- contributors can add a small analyzer rule with tests and docs,
- no default scan executes repository code.

## v0.2.x: Static Analyzer Expansion

Goal: improve the first analyzer set so real repositories receive more useful static feedback.

Planned analyzer work:

- repository documentation quality checks:
  - README installation section,
  - README quick start section,
  - README usage examples,
  - docs folder detection,
  - changelog quality signals,
  - broken-looking local links where safely detectable;
- GitHub Actions hardening checks:
  - self-hosted runner usage,
  - checkout credential persistence,
  - secret usage in pull request contexts,
  - script injection risk with `github.event.*`,
  - release workflow without visible test dependency,
  - upload/download artifact risk patterns,
  - overly broad permissions;
- secret scanner improvements:
  - more precise redaction tests,
  - high-entropy candidate detection with conservative confidence,
  - production config sensitive-value patterns,
  - more webhook/token families;
- Docker analyzer improvements:
  - `COPY . .` before dependency restore,
  - `apt-get update` and install layering risk,
  - missing `USER`,
  - secrets in `ENV`,
  - missing multi-stage build,
  - build context risk.

Reporting work:

- stronger console summary,
- clearer Markdown sections,
- top recommended actions,
- skipped/failed module visibility,
- better report-format documentation.

Out of scope:

- network lookups,
- package metadata clients,
- vulnerability analysis,
- license analysis,
- package-origin claims.

Success criteria:

- static scan output is useful on common GitHub repositories,
- false-positive-prone rules use conservative confidence,
- every new rule has fixture tests and public rule docs,
- Markdown reports are shareable in issues or PR comments.

## v0.3.x: Dependency Inventory

Goal: answer "what does this repository depend on?" without yet making vulnerability or legal claims.

Planned dependency artifacts:

- `DependencyInventoryArtifact`,
- ecosystem enum for NuGet, npm, and Python,
- manifest records,
- lockfile records,
- package records,
- package scope,
- direct/transitive marker where safely known,
- pinned/prerelease markers,
- deterministic metrics.

NuGet work:

- parse direct `PackageReference` entries safely,
- support nested `<Version>` nodes,
- support Central Package Management through `Directory.Packages.props`,
- detect floating, wildcard, missing, and prerelease versions,
- record NuGet package sources without network access.

npm work:

- parse `package.json` dependency sections,
- record `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`,
- detect unpinned/range/prerelease versions,
- record `packageManager` and `engines`,
- flag install-time scripts for manual review.

Python work:

- parse `requirements.txt`,
- parse `pyproject.toml` and `Pipfile` conservatively,
- detect unpinned requirements,
- detect lockfile coverage with Poetry, uv, and Pipenv.

Reporting work:

- dependency summary in Markdown,
- dependency counts by ecosystem,
- top dependency hygiene actions.

Out of scope:

- registry metadata,
- latest-version freshness,
- vulnerability lookup,
- license lookup,
- package origin trust.

Success criteria:

- dependency inventory is reusable by later analyzers,
- parser behavior is static-only and fixture-tested,
- malformed manifests do not crash scans,
- package names and versions are treated as untrusted text.

## v0.4.x: Vulnerability, License, and Package Origin Intelligence

Goal: turn dependency inventory into cautious risk intelligence.

Infrastructure work:

- safe network lookup abstraction,
- allowlisted hosts,
- timeouts,
- response size limits,
- cancellation,
- structured network errors,
- fixture-driven client tests.

Package metadata clients:

- NuGet metadata client,
- npm metadata client,
- PyPI metadata client,
- common package metadata model,
- license metadata normalization.

Risk analyzers:

- package freshness analyzer,
- OSV advisory client,
- dependency vulnerability analyzer,
- license analyzer,
- package origin analyzer,
- typosquatting heuristics,
- dependency confusion checks.

Reporting work:

- surface critical vulnerability findings ahead of lower-severity hygiene findings,
- show direct vs transitive distinction where known,
- show license uncertainty without making legal conclusions,
- use cautious package-origin language.

Out of scope:

- full SPDX legal interpretation,
- exploitability or reachability claims unless evidence exists,
- following package-provided URLs,
- downloading or executing packages.

Success criteria:

- registry and advisory access is isolated behind safe clients,
- vulnerability/license/origin findings are evidence-based,
- network failures produce partial results instead of scan failures,
- no finding claims a package is malicious without strong evidence.

## v0.5.x: API, Worker, Persistence, and Progress

Goal: prepare the hosted scan platform without putting analyzer logic into API endpoints.

API foundation:

- health endpoint,
- start scan endpoint,
- get scan status endpoint,
- get scan modules endpoint,
- get scan findings endpoint,
- get scan report endpoint,
- cancel scan endpoint.

Worker foundation:

- scan job contract,
- queue abstraction,
- worker execution loop,
- cancellation boundaries,
- analyzer timeout enforcement,
- failure isolation.

Persistence foundation:

- repository record,
- scan record,
- module record,
- finding record,
- score/report record,
- basic in-memory or lightweight persistence for early development.

Progress model:

- queued,
- preparing repository,
- running static analyzers,
- running dependency analyzers,
- scoring,
- reporting,
- completed,
- failed,
- cancelled.

Out of scope:

- public arbitrary file uploads without an intake policy,
- executing repository code,
- multi-tenant enterprise controls,
- full web UI.

Success criteria:

- hosted scan lifecycle can be represented end to end,
- API does not contain analyzer logic,
- worker can process a scan through the existing engine,
- scan status can be polled safely.

## v0.6.x: Trust Profiles and Policy Evaluation

Goal: answer "risky according to which usage scenario?"

Policy model:

- built-in policy presets for trust profiles,
- allowed and denied licenses,
- maximum vulnerability severity,
- minimum overall score,
- minimum category scores,
- required SECURITY.md,
- unpinned action handling,
- unknown license handling,
- release checksum requirement,
- allowed registry placeholders.

Evaluation work:

- policy evaluation result,
- policy violations,
- warnings,
- blocking risks,
- related finding fingerprints,
- selected policy name in reports.

Scoring work:

- profile-aware score adjustments,
- blocking risk override behavior,
- clearer final decision reasons,
- tests proving the same findings score differently under multiple profiles.

Out of scope:

- custom policy file language unless the model is stable,
- enterprise-specific legal conclusions,
- analyzer-enforced policy decisions.

Success criteria:

- analyzers still only produce evidence,
- policies decide acceptability,
- serious blocking risks cannot be hidden by high average scores,
- reports clearly show profile and policy impact.

## v0.7.x: Release and Supply-Chain Evidence

Goal: explain whether users can trust what a repository publishes.

Release hygiene analyzer:

- releases exist,
- tags exist,
- latest release age,
- changelog includes latest version,
- stable vs prerelease distinction,
- default branch drift from latest release.

Artifact trust analyzer:

- release artifacts exist,
- checksums exist,
- SBOM exists,
- provenance or attestation exists,
- signed tag/commit signals where safely available,
- Docker digest evidence where declared.

Release workflow analyzer:

- release workflow exists,
- release workflow depends on tests,
- release workflow permissions,
- package publish triggers,
- artifact creation steps,
- package publishing steps.

Version consistency:

- NuGet package version vs Git tag,
- npm package version vs Git tag,
- Python package version vs Git tag,
- release title vs tag consistency.

Out of scope:

- downloading arbitrary release artifacts by default,
- executing release artifacts,
- claiming cryptographic validity without verification.

Success criteria:

- release trust gaps are visible and evidence-backed,
- artifact integrity gaps are explained carefully,
- reports distinguish missing evidence from confirmed risk.

## v0.8.x: Deep Code Intelligence

Goal: add deeper static and imported-evidence signals about code quality and risk.

Coverage work:

- detect existing coverage reports,
- parse Cobertura XML,
- parse lcov,
- record line and branch coverage where available,
- report missing coverage as unknown/skipped instead of running tests.

Criticality work:

- identify auth/security/payment/database/file/network/crypto keyword areas,
- detect large files and broad exception patterns,
- approximate central files where static imports allow it,
- combine low coverage with high criticality.

Public API work:

- start with .NET public API surface where feasible,
- detect exported API changes from available snapshots,
- keep breaking-change claims conservative.

Out of scope:

- running test suites to generate coverage by default,
- full language call graphs,
- unsupported reachability claims.

Success criteria:

- Deep scan differs meaningfully from Standard scan,
- imported coverage is parsed safely,
- code-criticality findings are clearly heuristic.

## v0.9.x: History, Comparison, and Monitoring

Goal: make trust changes understandable over time.

History:

- store scan snapshots,
- track score trend,
- track category trend,
- track new and resolved findings.

Trust diff:

- compare two scans,
- compare branches/tags/commits where safe,
- show worsened, improved, new, and resolved risks.

Comparison:

- compare multiple repositories,
- highlight strongest signals and biggest risks,
- support dependency selection workflows.

Monitoring:

- scheduled scan model,
- trust regression alerts,
- stale release alerts,
- newly introduced critical finding alerts.

Out of scope:

- enterprise dashboard polish,
- notification provider sprawl,
- storing raw repository source files.

Success criteria:

- users can see why trust changed,
- comparison output is explainable,
- historical records avoid raw secret/source storage.

## v1.0.0: Stable Public Release

Goal: publish a stable, documented, contributor-friendly repository trust platform.

Stable by `v1.0.0`:

- analyzer abstraction,
- finding and evidence model,
- report JSON shape,
- CLI command structure,
- rule ID convention,
- basic scoring model,
- policy model,
- public documentation structure.

Required feature set:

- CLI scanning,
- API scanning,
- worker-based scan execution,
- progressive scan status,
- JSON and Markdown reports,
- repository health analysis,
- GitHub Actions security analysis,
- dependency inventory,
- vulnerability analysis,
- license analysis,
- package origin analysis,
- release hygiene analysis,
- secret quick scan,
- Docker analysis,
- trust profiles,
- policy evaluation,
- blocking risks,
- rule documentation,
- fixture-based analyzer tests.

Required documentation:

- README,
- installation guide,
- quick start,
- architecture,
- roadmap,
- analyzer authoring guide,
- rule authoring guide,
- policy configuration guide,
- report format documentation,
- contributing guide,
- security policy,
- code of conduct.

Success criteria:

- developers can use the tool before adopting dependencies,
- maintainers can use reports to improve repositories,
- security-minded users can identify major supply-chain risks,
- contributors can add analyzers without understanding the whole system,
- limitations and uncertainty are visible in reports.

## Roadmap Rules

- Do not execute untrusted repository code by default.
- Do not add analyzers that produce findings without evidence.
- Do not mix detection, scoring, and policy decisions.
- Do not implement network lookups outside safe clients.
- Do not make malware, legal, or exploitability claims without strong evidence.
- Add tests and public rule docs for every new rule.
- Keep reports useful when some modules fail or are skipped.
