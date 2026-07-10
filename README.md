# Repository Trust Doctor

[![CI](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml/badge.svg)](https://github.com/Wezylnia/repo-trust-doctor/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/Wezylnia/repo-trust-doctor?include_prereleases)](https://github.com/Wezylnia/repo-trust-doctor/releases)
[![License](https://img.shields.io/github/license/Wezylnia/repo-trust-doctor)](LICENSE)

**Make an evidence-backed decision before a repository becomes your dependency.**

Repository Trust Doctor turns scattered open-source signals—security posture, dependency risk, release evidence, maintenance, CI/CD, infrastructure, containers, and code intelligence—into an explainable recommendation:

- **Use with confidence** when the evidence fits your intended use.
- **Fix before adopting** when a small number of risks need resolution.
- **Avoid for this profile** when the repository does not meet the required bar.

It is a local-first, static analysis platform for engineers evaluating a library, service, image, tool, or repository before it reaches production. Findings always include a rule ID, severity, confidence, evidence, and a recommended next step. The final score never silently hides policy-blocking risks.

> Current development line: **v0.9.5**. The scanner does not execute repository code by default.

## What decision does it help you make?

| Before you adopt | Repo Trust Doctor gives you |
| --- | --- |
| “Can we use this in production?” | A profile-aware recommendation and the exact reasons behind it. |
| “What should we fix first?” | Prioritized findings, evidence paths, recommendations, and a report for the team. |
| “Can we enforce this in CI?” | JSON, Markdown, and SARIF output plus score/severity gates. |
| “Did this repository get safer or riskier?” | Stable finding fingerprints and report diff support. |

## Start in three steps

Requirements: **.NET 10 SDK** and **Git**.

```text
git clone https://github.com/Wezylnia/repo-trust-doctor.git
cd repo-trust-doctor
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan https://github.com/owner/repo --depth standard --profile production
```

The command prints a decision and a score. Use the profile that matches the consequence of being wrong:

| Profile | Use it when |
| --- | --- |
| `personal` | You are evaluating an experiment, prototype, or low-impact project. |
| `production` | The repository may become a production dependency, service, image, tool, or build input. |
| `security` | It handles credentials, authorization, sensitive data, infrastructure control, or another high-impact workload. |

For a more complete code and dependency review, use `--depth deep`. Fast scans are useful for an initial signal; standard is the recommended default for adoption decisions.

## See the answer, then the evidence

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --depth standard --profile production --format markdown --output reports/trust-review.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format sarif --output reports/trust-review.sarif
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff reports/before.json reports/after.json --format markdown
```

Each report has three layers:

1. **Recommendation** — a policy-aware decision for the selected risk profile.
2. **Next steps** — the small set of reasons to resolve before adoption.
3. **Evidence and coverage** — every finding, its source path, and any partial or unavailable checks.

Exit code `3` means the scan completed but the selected profile decided `AvoidAsProductionDependency`; this is a decision, not a tool failure. Exit code `4` means a configured CI gate failed. Full semantics are in [CLI exit codes](#cli-exit-codes).

## Local workbench

Use the React workbench when you want an adoption review that is easy to share with a team. Enter a public GitHub repository as `owner/repo`, choose the intended use, and drill from recommendation to evidence. It displays scan coverage so a missing external service or bounded analyzer is never presented as a clean result.

```text
dotnet run --project src/Apps/RepoTrustDoctor.Api --urls http://localhost:5000

cd src/Apps/RepoTrustDoctor.Web
npm install
npm run dev
```

The web app asks the local API to scan `https://github.com/owner/repo`. The API accepts public absolute GitHub URLs and rejects local paths, credentials, query strings, and fragments. Read [the web workbench guide](docs/web-ui.md) for the flow and [the API and worker guide](docs/api-worker.md) for endpoint details.

## What it checks today

Repository Trust Doctor is deliberately broad enough for a real adoption review, while keeping detection separate from scoring and policy.

### Supply chain and dependencies

- Dependency inventory and lockfile coverage across npm, NuGet, Python, Maven, Gradle, Go, Cargo, Composer, Ruby, Dart/Pub, Elixir/Hex, SwiftPM, and C/C++.
- Static package-origin, version, prerelease, install-script, dependency consistency, license, freshness, vulnerability, and dependency-confusion signals.
- SQLite-backed package metadata caching and local OSV advisory indexing with conservative online fallback.
- SBOM, provenance, checksum, package-version, and release-evidence correlation.

### Delivery and infrastructure

- GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI security rules.
- Dockerfile and Docker Compose hygiene.
- Kubernetes and Terraform security checks.
- Repository health, security policy, CODEOWNERS, toolchain, release, and maintenance signals.

### Code and reporting

- Redacted secret quick scanning and safe handling of repository-derived text.
- Deep code intelligence for coverage, critical areas, public APIs, imports, framework routes, deserialization, and command execution heuristics.
- Deterministic JSON, Markdown, and SARIF reports with stable finding fingerprints.
- Policy-aware scoring, suppressions with reasons and expiration, report diffs, and CI gate thresholds.

See the [rule reference](docs/rules/README.md) for every rule family and [report format](docs/report-format.md) for the output contract.

## Safe by default

Repositories are untrusted input. The default scan path performs static file analysis and safe metadata lookups; it does not execute repository code. Remote repositories are shallow-cloned without submodules, unsafe Git protocols are disabled, traversal skips reparse points and heavy generated directories, and report writers escape repository-derived text.

When a check cannot complete, the result is reported as partial or unavailable. Downstream checks do not convert missing prerequisite evidence into a clean result. Details are in [Architecture](docs/architecture.md) and [Security](SECURITY.md).

## Use it in CI

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile production --fail-under 75
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --profile security --fail-on-severity High
```

Use JSON or SARIF for automation, and Markdown when a human needs to review the result. The included [PR trust analysis workflow](.github/workflows/pr-trust-analysis.yml) is a concrete starting point.

## Architecture

The platform separates **detection** from **interpretation**:

```text
Apps (CLI, API, Worker, React workbench)
        ↓
Application scan lifecycle + scan runner
        ↓
Analyzers produce evidence and findings
        ↓
Scoring and policies produce the recommendation
        ↓
JSON / Markdown / SARIF / UI
```

`Core` contains the domain and application contracts. `Engine` owns analyzer execution, orchestration, scoring, policies, and reporting. Independent modules in `Analyzers` detect evidence. `Infrastructure` implements Git workspaces, metadata clients, local intelligence, and the shared scan runner. This lets CLI, API, and worker hosts produce the same report from the same analyzer pipeline.

Read the [architecture overview](docs/architecture.md), [analyzer authoring guide](docs/analyzer-authoring.md), and [local intelligence guide](docs/local-intelligence.md).

## Validate a change

```text
dotnet restore RepoTrustDoctor.slnx --locked-mode
dotnet test RepoTrustDoctor.slnx

cd src/Apps/RepoTrustDoctor.Web
npm ci
npm test
npm run build
npm run test:visual
```

The project uses focused analyzer fixtures and a rotating corpus of large public repositories to catch precision, coverage, and performance regressions. See [quality validation](docs/quality-validation.md).

For repeatable local timing, use the built-in benchmark command. It disables the completed-scan cache so each measured iteration runs the analyzers:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- benchmark . --iterations 5 --warmup 1 --depth deep --profile production
```

## CLI exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed without a blocking avoid decision. |
| `1` | CLI usage error. |
| `2` | Input or output error, such as refusing to overwrite a report. |
| `3` | Scan completed with `AvoidAsProductionDependency`. |
| `4` | Configured CI gate failed. |

## Contribute

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), then look for [good first issues](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22) or [help wanted](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22). Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## Scope and disclaimer

Repository Trust Doctor provides heuristic, evidence-based review. It does not certify that a repository, dependency, workflow, package, or release is secure, safe, compliant, or free from vulnerabilities. Use its findings as input to an engineering decision, not as a substitute for security review.
