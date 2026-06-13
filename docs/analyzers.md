# Analyzer Coverage

Repository Trust Doctor analyzers are evidence producers. They read repository files and safe metadata sources, emit findings with rule IDs and evidence, and leave scoring or policy decisions to the engine.

Default scans do not execute repository code, install packages, run tests, run builds, or build containers.

## Repository Health

Checks adoption and maintenance signals that users expect before trusting a repository:

- README presence, including common root formats such as Markdown, reStructuredText, AsciiDoc, plain text, and extensionless README files,
- LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CODEOWNERS, issue and pull request templates,
- changelog and documentation directory presence, including `docs`, `doc`, `documentation`, and `guides`,
- broken-looking local links in README files.

## GitHub Actions

Reviews `.github/workflows/*.yml` and `.yaml` files for common CI/CD trust risks:

- broad workflow permissions,
- self-hosted runners,
- `pull_request_target` usage,
- unpinned external actions,
- checkout credential persistence,
- script injection patterns using event data,
- release workflows without visible test dependencies,
- broad artifact upload paths.

The analyzer is static-only and does not run workflow jobs.

## Secret Quick Scan

Searches candidate text/config/source files for high-signal secret-like patterns and sensitive files. Evidence is redacted so reports do not become a new secret exposure path.

The scanner avoids binary files, oversized text files, and common generated, vendored, fixture, example, test, and documentation paths. Sensitive files such as `.env`, `.npmrc`, `.pypirc`, private-key extensions, and credential files are still surfaced when they appear in production paths.

## Docker And Containers

Reviews Dockerfiles and common container files for build and runtime hygiene:

- `latest` base image tags,
- missing `.dockerignore`,
- root user risk,
- missing `HEALTHCHECK`,
- secret-like `ENV` values,
- missing multi-stage builds,
- broad build context and cache-layering risks.

Container checks apply automatically when container files are present.

## Dependency Inventory

Builds a structured dependency inventory artifact from supported package manifests. The inventory records manifests, lockfiles, package names, versions, directness, scope, pinned status, prerelease status, package sources, and ecosystem metrics.

Current ecosystem collectors:

- npm: `package.json`, npm/pnpm/Yarn lockfiles including ancestor workspace lockfiles, dependency sections, install-time scripts, direct Git/URL sources, local sources, and workspace references.
- NuGet: `.csproj`, `Directory.Packages.props`, `packages.lock.json`, `NuGet.config`, direct `PackageReference` versions, Central Package Management versions, MSBuild property-based versions, package sources.
- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned requirement checks, documentation/test manifest suppression.
- Maven and Gradle: `pom.xml`, `build.gradle`, `build.gradle.kts`, Java lock evidence, BOM and dependency-management version signals, dynamic versions, snapshots/prereleases, Gradle wrapper evidence.
- Spring Boot: static configuration checks for broad Actuator endpoint exposure.

The inventory analyzer is split into per-ecosystem collectors so future language support can be added without growing one large analyzer class.

## Dependency Risk Intelligence

Consumes dependency inventory and safe package metadata/advisory clients:

- package metadata collection for npm, NuGet, PyPI, and Maven Central with duplicate package lookup suppression,
- dependency freshness checks,
- deprecated or yanked package checks,
- OSV advisory lookup for known vulnerabilities with duplicate package/advisory reporting suppression,
- license metadata review,
- package origin and repository URL comparison,
- dependency confusion review signals for npm and NuGet source configuration.

Network access is restricted to safe clients with allowlisted hosts, timeouts, response-size limits, cancellation, and isolated failure behavior.

## Release Evidence

Reviews release and publishing evidence without downloading arbitrary artifacts by default:

- changelog alignment with release versions,
- package version metadata alignment with tags,
- release workflow presence,
- checksum evidence,
- SBOM evidence,
- provenance or attestation evidence.

The analyzer distinguishes missing evidence from confirmed compromise.

## Codebase Intelligence

Deep scan analyzers import or infer code quality and change-risk signals:

- Cobertura XML and lcov coverage import,
- missing or low coverage signals,
- critical-code heuristics for auth, authorization, payments, data access, file operations, networking, cryptography, secrets, deserialization, and command execution,
- large file and broad exception handling signals,
- correlation between critical code and weak coverage,
- multi-language public API surface extraction and baseline diff review,
- static import graph centrality analysis,
- framework route detection for common web stacks.

Deep code intelligence remains conservative. It does not run tests or build projects to generate coverage, and it skips common sample, fixture, analyzer implementation, test, generated, third-party, and vendored static-library paths for route and criticality heuristics. On very large repositories, expensive codebase analyzers complete with warnings and truncation metrics rather than timing out.

## Policy, Scoring, And Reports

Scoring and policy evaluation are not analyzers, but they interpret analyzer output:

- category scores and overall score,
- blocking risk handling,
- trust profile decisions,
- policy violations,
- JSON, Markdown, SARIF, API, worker, and React report surfaces.

Reports should make uncertainty visible and keep findings traceable to evidence.

## History And Comparison

History and comparison features derive compact snapshots from scan reports:

- score and category deltas,
- new, resolved, worsened, improved, and unchanged findings,
- repository comparison models,
- scheduled scan and regression alert models.

Snapshots avoid storing raw repository source files or secrets.
