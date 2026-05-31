# Roadmap

Repository Trust Doctor will grow by stabilizing the analyzer platform first, then adding analysis depth.

## Current Alpha Release

`v0.1.0-alpha` is an early CLI-first static scanner. It includes the foundation platform, first static analyzers, dependency lockfile coverage checks, typed trust profile recording, stable finding fingerprints, and public rule/security documentation.

Package metadata lookup, vulnerability lookup, license analysis, package origin analysis, SARIF output, API/worker hosting, persistence, and web UI remain future work.

## Milestones

| Version | Goal |
| --- | --- |
| `v0.1` | Core architecture, analyzer engine, and first local static scan |
| `v0.2` | Repository, workflow, secret, Docker, and report improvements |
| `v0.3` | Dependency inventory and package metadata |
| `v0.4` | Vulnerability, license, package origin, typosquatting, and dependency confusion |
| `v0.5` | API, worker, persistence, and progressive scan state |
| `v0.6` | Trust profiles, policies, blocking risks, and score customization |
| `v0.7` | Release hygiene, artifact trust, and supply-chain evidence |
| `v0.8` | Coverage, code criticality, public API, and deep analysis |
| `v0.9` | History, comparison, trust diff, and monitoring |
| `v1.0` | Stable documented platform with reliable reports |

## v0.1 Scope

The foundation milestone includes:

- domain concepts for scans, modules, findings, evidence, recommendations, severity, confidence, scores, and decisions,
- analyzer abstraction with metadata, depth, dependencies, execution safety, and cancellation,
- basic orchestration and failure isolation,
- basic severity-based scoring,
- JSON and Markdown report writers,
- CLI command entry point,
- local path scans and shallow-cloned public HTTP(S) Git URL scans,
- fixture-based tests.

Initial analyzers:

- repository health,
- GitHub Actions basic security,
- secret quick scan,
- Docker basic checks.

Out of scope for `v0.1`:

- React UI,
- hosted scanning,
- database persistence,
- dependency vulnerability analysis,
- license analysis,
- package registry integration,
- historical scans,
- policy engine.

## Development Order

1. Build the solution skeleton.
2. Add the domain model and analyzer abstractions.
3. Add the engine, orchestration, scoring, and reporting foundation.
4. Add first static analyzers.
5. Stabilize CLI output and fixture tests.
6. Expand analyzers only after the engine remains clean.
