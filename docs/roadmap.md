# Roadmap

Repository Trust Doctor is a local-first, evidence-backed repository adoption workbench. The roadmap keeps detection, scoring, policy, and presentation separate while preserving a static-only default safety boundary.

## Current Release: v1.0.0

The stable v1 contract includes:

- local and public GitHub repository scans through the CLI,
- local GitHub scans through the API and React workbench,
- process-local API and worker scan lifecycle, progress, cancellation, and exports,
- deterministic JSON, Markdown, and SARIF reports,
- stable finding fingerprints, report diffing, suppressions, trust profiles, scoring, and policy decisions,
- repository health, secrets, CI/CD, container, infrastructure, release, dependency, license, vulnerability, origin, and deep code intelligence,
- dependency inventory across npm, NuGet, Python, Maven, Gradle, Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++,
- bounded analyzer concurrency, shared source indexing, local dependency intelligence, and repeatable performance benchmarks,
- self-contained Windows, Linux, and macOS CLI archives and a packaged .NET tool,
- contributor, rule, report, architecture, API, security, and validation documentation.

Default scans do not execute repository code, install packages, run builds or tests, start containers, or initialize infrastructure.

## v1.1: Adoption Workflow

Goal: make recurring local reviews faster and easier to compare.

- report comparison views in React,
- scan history stored locally without raw repository source,
- branch and tag comparison commands,
- clearer baseline and suppression management,
- richer remediation links and export workflows,
- accessibility and keyboard-navigation review.

## v1.2: Ecosystem Precision

Goal: deepen existing ecosystem support without inflating low-confidence findings.

- lockfile and workspace edge cases across supported package managers,
- improved monorepo project association,
- conservative reachability and dependency-to-code correlation,
- broader imported SBOM, provenance, and SARIF correlation,
- language-specific code intelligence precision work,
- corpus-backed false-positive budgets per analyzer family.

## v1.3: Analyzer Extension Contract

Goal: make third-party analyzers possible without weakening scan safety.

- analyzer template and fixture harness,
- machine-validated rule metadata and documentation,
- analyzer package manifest,
- report and API compatibility fixtures,
- explicit capability declarations for filesystem, network, and future sandboxed execution,
- compatibility policy for external analyzer packages.

## v1.4: Durable Local Product

Goal: support long-running single-user or team-local installations.

- persistence adapter for scan summaries, reports, modules, and findings,
- durable queue adapter,
- retention and cleanup controls,
- scheduled scans and local notifications,
- retry and recovery behavior,
- API compatibility negotiation in the React client.

Persisted reports must not contain raw repository source or unredacted secret values.

## v2.0: Hosted Trust Platform

Hosted or multi-tenant operation is intentionally not promised by v1.x until these boundaries exist:

- authentication and authorization,
- tenant-aware queues and storage,
- rate, concurrency, clone-size, and retention limits,
- private-repository credential isolation,
- audit logging and administrative controls,
- sandbox policy for any future opt-in execution,
- stable public plugin and API versioning.

## Roadmap Rules

- Do not execute untrusted repository code by default.
- Do not emit findings without evidence and a recommended action.
- Do not mix analyzer detection with scoring or profile policy.
- Do not perform network lookups outside bounded, validated clients.
- Do not treat missing or partial evidence as a clean result.
- Do not make exploitability, malware, legal, or certification claims without strong evidence.
- Add focused tests and public documentation for every new rule.
- Preserve deterministic reports and stable finding identity across performance changes.
