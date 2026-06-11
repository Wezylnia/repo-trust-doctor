# Roadmap

Repository Trust Doctor grows in layers: first the static analyzer platform, then dependency intelligence, then policy-aware risk decisions, then hosted scanning and deeper trust signals.

The roadmap is intentionally conservative. Each milestone should leave the project easier to extend, not just larger.

## Current Release

`v1.5.0` is a stable static scanner and local platform focused on repository documentation quality, GitHub Actions and GitLab CI security, Docker/Compose/Kubernetes hygiene, secret quick scanning, structured dependency inventory across npm, NuGet, Python, Maven, Gradle, Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++ package manager evidence, Spring Boot configuration signals, dependency risk intelligence, policy-aware scoring, SARIF output, release and imported evidence review, deep code intelligence, trust history/diff, deterministic reports, CI gate options, API/worker-hosted scan flows, and a local React scan workbench.

Current scans are static-only by default. The tool does not execute repository code, install packages, run tests, run builds, or build containers as part of a scan.

## Milestone Summary

| Version | Theme | Main Outcome |
| --- | --- | --- |
| `v0.1.x` | Foundation alpha | Local static scans, report output, basic analyzers, CI gates |
| `v0.2.x` | Static analyzer expansion | Better repository, workflow, secret, Docker, and report quality |
| `v0.3.x` | Dependency inventory | Structured NuGet, npm, and Python dependency artifacts |
| `v0.4.x` | Risk intelligence | Safe metadata/advisory clients, vulnerability, license, freshness, origin, dependency confusion |
| `v0.5.x` | Reporting and progress foundation | SARIF output and progress DTOs |
| `v0.6.x` | Policies and profiles | Built-in policies, blocking risks, profile-aware scoring |
| `v0.7.x` | Release trust | Release hygiene, artifact integrity, SBOM/provenance evidence |
| `v0.8.x` | Deep code intelligence | Coverage import, code criticality, public API risk |
| `v0.9.x` | History and comparison | Trust diff, historical trend, repository comparison, monitoring models |
| `v1.0.x` | Stable public release | Current: stable contracts, API/worker hosts, React scan workbench, documented reports |
| `v1.1.0` | Java and Spring Boot support | Maven/Gradle inventory, Maven metadata/advisory lookup, Spring Boot Actuator exposure checks |
| `v1.2.x` | More dependency ecosystems | Go, Rust, PHP, Ruby, Swift, Dart/Flutter, Elixir, and C/C++ package manager inventory |
| `v1.3.x` | Monorepo and workspace intelligence | Better workspace grouping, package manager workspace support, per-project summaries |
| `v1.4.x` | CI/CD and IaC expansion | GitLab CI, Azure Pipelines, CircleCI, Kubernetes, Helm, Terraform, and Compose review |
| `v1.5.x` | Evidence integrations | SBOM import, provenance import, external SAST/SCA result import, richer advisory correlation |
| `v1.6.x` | Durable scan product | Persistence, scan history UI, report comparison UI, API-backed exports |
| `v1.7.x` | Deeper static code intelligence | Language-specific API extractors, static import/dependency graphs, conservative reachability hints |
| `v1.8.x` | Analyzer SDK and plugins | Stable analyzer packaging, rule metadata validation, external analyzer test harness |
| `v1.9.x` | Hosted hardening | Tenant-safe queues, storage controls, rate limits, private repository credential isolation |
| `v2.0.0` | Extensible trust platform | Stable plugin-ready platform with broad ecosystem coverage and durable operational workflows |

## v0.1.x: Foundation Alpha

Goal: make the project useful as a local static scanner and stable enough for analyzer contributors.

Delivered:

- modular .NET solution structure,
- pure domain model for scans, modules, findings, evidence, recommendations, scores, and decisions,
- analyzer abstraction with metadata, scan depth, dependencies, execution safety, timeout, and cancellation,
- isolated analyzer execution and partial-result behavior,
- local path scans and shallow public HTTP(S) Git URL scans,
- console, JSON, Markdown, and SARIF report output,
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

Delivered in `v0.2.0`:

- repository documentation quality checks:
  - README installation section,
  - README quick start section,
  - README usage examples,
  - docs folder detection,
  - changelog detection,
  - broken-looking local README links;
- GitHub Actions hardening checks:
  - self-hosted runner usage,
  - checkout credential persistence,
  - script injection risk with `github.event.*`,
  - release workflow without visible test dependency,
  - broad artifact upload paths,
  - overly broad permissions;
- secret scanner improvements:
  - redacted evidence for token, key, webhook, and connection string-like values,
  - sensitive file detection,
  - binary and fixture suppression safeguards;
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

Remaining `v0.2.x` follow-up candidates:

- high-entropy secret candidates with conservative confidence,
- more precise workflow pull request secret-context checks,
- download-artifact trust checks,
- README configuration/troubleshooting section checks,
- Markdown report action prioritization.

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

Delivered in `v0.3.0`:

- `DependencyInventoryArtifact`,
- ecosystem enum for NuGet, npm, and Python,
- manifest records,
- lockfile records,
- package records,
- package scope,
- direct/transitive marker where safely known,
- pinned/prerelease markers,
- deterministic metrics.

NuGet work delivered:

- parse direct `PackageReference` entries safely,
- support nested `<Version>` nodes,
- support Central Package Management through `Directory.Packages.props`,
- detect floating, wildcard, missing, and prerelease versions,
- record NuGet package sources without network access.

npm work delivered:

- parse `package.json` dependency sections,
- record `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`,
- detect unpinned/range/prerelease versions,
- record `packageManager` and `engines`,
- flag install-time scripts for manual review.

Python work delivered:

- parse `requirements.txt`,
- parse `pyproject.toml` and `Pipfile` conservatively,
- detect unpinned requirements,
- detect lockfile coverage with Poetry, uv, and Pipenv.

Reporting work delivered:

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

Delivered in `v0.4.0` and `v0.4.1`:

- static npm direct remote source detection,
- static npm local source detection,
- static NuGet insecure HTTP source detection,
- static NuGet local path source detection,
- package source local and secure-transport artifact fields,
- dependency inventory metrics for origin risk signals,
- Markdown report summary fields for package-origin review.

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
- running fast modules,
- running static analyzers,
- running dependency analyzers,
- running security analyzers,
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

- changelog includes latest version,
- package version metadata aligns with changelog release headings.

Artifact trust analyzer:

- checksums exist,
- SBOM exists,
- provenance or attestation exists.

Release workflow analyzer:

- release workflow exists,
- package publish triggers,
- artifact integrity evidence steps.

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

Delivered in `v0.8.0`:

- detect existing coverage reports,
- parse Cobertura XML,
- parse lcov,
- record line and branch coverage where available,
- report missing coverage as unknown/skipped instead of running tests,
- identify auth/security/payment/database/file/network/crypto keyword areas,
- detect large files and broad exception patterns,
- combine low coverage with high criticality,
- start with .NET public API surface where feasible,
- detect exported API changes from available snapshots,
- keep breaking-change claims conservative.

Remaining `v0.8.x` follow-up candidates:

- approximate central files where static imports allow it,
- add language-specific API extractors beyond .NET,
- improve coverage path matching for monorepos.

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

Delivered in `v0.9.0`:

- derive compact scan snapshots from reports,
- track score and category deltas,
- track new, resolved, worsened, improved, and unchanged findings,
- compare two JSON scan reports with the CLI `diff` command,
- compare multiple repository snapshots in the engine layer,
- provide a scheduled scan model,
- provide score, decision, new blocking, and new high-severity regression alerts.

Remaining `v0.9.x` follow-up candidates:

- compare branches/tags/commits by running scans into temporary reports,
- stale release regression alerts,
- richer repository comparison report output.

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
- API scan lifecycle contract,
- worker job processing contract,
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

Delivered in `v1.0.0`:

- shared application scan lifecycle services,
- in-memory scan store and job queue for local hosting,
- cancellation-aware scan processing,
- central repository scan runner used by CLI, API, and worker,
- API endpoints for health, start, list, status, progress, modules, findings, reports, and cancellation,
- Worker host using the shared queued scan processor,
- API/worker documentation and local smoke-test guidance.

Remaining post-1.0 candidates:

- durable persistence adapter,
- shared queue adapter for API/worker split deployments,
- scheduled scan execution,
- hosted notification providers,
- branch/tag comparison commands that run scans into temporary reports.

## v1.0.5: React Workbench Update

Goal: make the React app feel like a serious operational scan console.

Delivered in `v1.0.5`:

- the web app opens on the backend scan flow by default,
- completed API scans automatically load into the report workspace,
- the visual design is flatter, denser, and more work-focused,
- report review now foregrounds final decision reasons and category scores,
- web unit tests cover selector behavior and API scan helper behavior,
- the API allows configured local web origins for local development.

## v1.0.6: GitHub-First React Scan Flow

Goal: remove raw JSON and saved-report handling from the React user flow.

Delivered in `v1.0.6`:

- removed saved report/import UI,
- removed sample report loading from the UI,
- locked the scan target to GitHub repositories,
- normalized pasted GitHub URLs into `owner/repo`,
- hid the local backend URL from the user-facing form,
- emphasized the overall 100-point score at the top of the report with score color bands:
  - `90+`: dark green,
  - `80-89`: green,
  - `60-79`: yellow,
  - `<60`: red.

Out of scope:

- arbitrary local path scanning from React,
- raw JSON upload/import from React,
- public hosted scanning.

Out of scope:

- public hosted scanning,
- authentication and authorization,
- durable report history,
- multi-user file intake.

## v1.1.0: React And Backend Scan Experience

Goal: continue turning the local API and React app into a coherent scan product.

Planned work:

- API health and version compatibility checks in React,
- module-level live progress rendering while a scan is running,
- clearer failed/cancelled scan recovery states,
- persistence adapter for scan summaries and completed reports,
- report history view backed by persisted scan records,
- backend report export actions from the React UI,
- scan comparison flow driven by completed backend scan IDs,
- stronger API integration tests around CORS, status, report fetch, and cancellation.

Safety boundaries:

- default scans remain static-only,
- no public arbitrary upload endpoint without an intake policy,
- no execution of repository code,
- saved reports and persisted records must not store raw secrets.

## v1.2.x: Dependency Ecosystem Expansion

Goal: make dependency inventory useful across the most common open-source stacks without weakening the static-only safety model.

Candidate ecosystem work:

- Go: parse `go.mod` and `go.sum`, record module versions, flag missing `go.sum`, review `replace` directives, support OSV Go advisories.
- Rust: parse `Cargo.toml` and `Cargo.lock`, flag Git/path dependencies, consume crates.io metadata, support yanked/deprecated crate evidence and RustSec or OSV advisories.
- PHP: parse `composer.json` and `composer.lock`, support Packagist metadata, identify abandoned packages and platform constraints.
- Ruby: parse `Gemfile`, `Gemfile.lock`, and `.gemspec`, flag Git/path gems, support RubyGems metadata and yanked gem evidence.
- Swift: parse `Package.swift` and `Package.resolved`, flag branch-based package dependencies and unclear package URL provenance.
- Dart and Flutter: parse `pubspec.yaml` and `pubspec.lock`, distinguish hosted, path, and Git dependencies, support pub.dev metadata.
- Elixir and Erlang: parse `mix.exs`, `mix.lock`, and `rebar.config`, support Hex metadata.
- C and C++: detect Conan, vcpkg, and CMake dependency declarations, record package manager evidence, and flag vendored dependency folders conservatively.
- Android and Kotlin: parse Gradle version catalogs such as `libs.versions.toml` and improve plugin/dependency version extraction.

Implementation shape:

- add one collector per ecosystem,
- add safe metadata clients only behind allowlisted network abstractions,
- add OSV ecosystem mapping where OSV supports it,
- keep parser failures isolated to the related manifest,
- update rule docs and language-support docs for every new rule.

Success criteria:

- no collector file grows beyond the maintainability limit,
- each ecosystem has synthetic fixture tests,
- scans remain static-only,
- unsupported constructs are reported as unknown or skipped, not guessed.

## v1.3.x: Monorepo And Workspace Intelligence

Goal: explain large repositories by project/workspace rather than one flat package list.

Planned work:

- npm, pnpm, Yarn, NuGet solution, Gradle multi-project, Maven reactor, Cargo workspace, Go workspace, Composer workspace, and Dart workspace detection,
- per-project dependency summaries,
- workspace-local dependency edge recording,
- duplicated package/version drift detection,
- generated/vendor directory handling tuned per ecosystem.

Success criteria:

- reports show which project produced which finding,
- monorepos remain readable in CLI, Markdown, API, and React reports,
- workspace support does not require executing package managers.

## v1.4.x: CI/CD And Infrastructure Coverage

Goal: widen supply-chain review beyond GitHub Actions and Dockerfiles.

Candidate analyzers:

- GitLab CI: privileged jobs, broad artifacts, unpinned includes, shell injection patterns, protected-branch publish jobs.
- Azure Pipelines: service connection exposure, script injection patterns, broad artifact publishing, unpinned tasks.
- CircleCI: orb pinning, broad contexts, workspace/artifact exposure.
- Kubernetes and Helm: privileged pods, hostPath mounts, broad capabilities, missing resource limits, risky image tags.
- Terraform: public ingress, wildcard IAM, unencrypted storage, missing state backend guidance.
- Docker Compose: privileged services, host mounts, broad port exposure, latest images.

Success criteria:

- infrastructure findings use cautious language,
- every rule has evidence and docs,
- generated or vendored YAML does not dominate reports.

## v1.5.x: Evidence Import And Correlation

Goal: let teams reuse existing security evidence without making RepoTrustDoctor a replacement for every scanner.

Planned imports:

- SPDX and CycloneDX SBOM files,
- SLSA/in-toto provenance evidence,
- GitHub code scanning SARIF,
- Semgrep SARIF,
- CodeQL SARIF,
- Trivy/Grype vulnerability reports,
- Dependabot and GitHub Advisory evidence where available.

Correlation work:

- map imported evidence to repository files and dependency packages,
- deduplicate equivalent findings across sources,
- preserve source tool names,
- avoid claiming imported results are verified by RepoTrustDoctor.

## v1.6.x: Durable API And React Product

Goal: turn the local workbench into a durable operational workflow.

Planned work:

- persistence adapter for scan summaries, reports, modules, findings, and trend snapshots,
- scan history and comparison views in React,
- retry and cancellation UX,
- backend report export from completed scan IDs,
- API compatibility checks in the React app,
- retention controls for reports and evidence.

Safety boundaries:

- persisted reports must not store raw repository source,
- secrets remain redacted,
- private repository credentials require separate isolation design.

## v1.7.x: Deeper Static Code Intelligence

Goal: improve source risk understanding while staying conservative.

Candidate work:

- TypeScript, Python, Java, Go, and Rust public API extractors,
- static import/dependency graphs for central file detection,
- framework route/controller detection for common stacks,
- security-sensitive API usage heuristics for auth, crypto, file IO, network IO, and deserialization,
- coverage matching improvements for monorepos.

Out of scope:

- default execution-based reachability,
- exploitability claims,
- full language call graphs for unsupported languages.

## v1.8.x: Analyzer SDK And Plugin Readiness

Goal: make external analyzers easier to build safely.

Planned work:

- analyzer template project,
- rule metadata validator,
- fixture test harness,
- analyzer package manifest,
- documentation checks for new rules,
- compatibility tests against report JSON shape.

Success criteria:

- a contributor can add a new analyzer without understanding the whole engine,
- third-party analyzers cannot bypass scan safety rules by default.

## v1.9.x: Hosted Hardening

Goal: prepare the project for serious hosted or team deployment.

Planned work:

- tenant-aware scan queue and storage boundaries,
- rate limits and repository size limits,
- worker isolation policy,
- private repository credential isolation,
- audit log model,
- retention and deletion controls,
- abuse-resistant URL intake validation.

Out of scope:

- enabling execution-based scans without a separate sandboxed pipeline,
- treating hosted scan output as certification.

## v2.0.0: Extensible Trust Platform

Goal: graduate from a static scanner with a local workbench into an extensible trust review platform.

Expected shape:

- broad dependency ecosystem inventory,
- multiple CI/CD and infrastructure analyzers,
- durable API and React workflows,
- stable analyzer SDK,
- plugin-ready analyzer boundaries,
- evidence import and correlation,
- clear safety model for local, hosted, and future sandboxed deep scans.

Success criteria:

- the v2 API/report/plugin contracts are stable enough for external integration,
- scans are explainable and evidence-first,
- adding a new ecosystem does not require large core rewrites,
- safety boundaries remain visible in docs and product UX.

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
