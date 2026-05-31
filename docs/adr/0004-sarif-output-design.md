# ADR 0004: SARIF Output Design

Status: Proposed

## Context

SARIF is useful because GitHub code scanning and other security tools can ingest structured analysis results, show findings inline with source locations, track alerts across runs, and suppress duplicate noise when stable fingerprints are available.

Repository Trust Doctor currently emits JSON and Markdown reports. Those reports already include structured rule IDs, categories, severity, confidence, evidence, recommendations, and stable finding fingerprints. Full SARIF output should build on that model rather than become a separate analyzer output path.

## Decision

Future SARIF output should be produced by the reporting layer from `RepositoryScan` and `Finding` models.

| RepoTrustDoctor field | SARIF target |
| --------------------- | ------------ |
| `Finding.RuleId` | `result.ruleId` and `tool.driver.rules[].id` |
| `Finding.Title` | `result.message.text` and rule `shortDescription.text` |
| `Finding.Message` | `result.message.text` detail when it adds context |
| `Finding.Recommendation.Message` | rule `help.text` or `help.markdown` |
| `Finding.Severity` | `result.level` using `error`, `warning`, `note`, or `none` mapping |
| `Finding.Confidence` | `result.properties.confidence` |
| `Finding.Category` | rule `properties.category` and optional `properties.tags` |
| `Finding.Evidence.FilePath` | `result.locations[].physicalLocation.artifactLocation.uri` |
| `Finding.Evidence.LineNumber` | `result.locations[].physicalLocation.region.startLine` |
| `Finding.Evidence.Kind` | `result.properties.evidenceKind` |
| `Finding.Tags` | `result.properties.tags` |
| `Finding.IsBlocking` | `result.properties.isBlocking` |
| `Finding.Fingerprint` | `result.partialFingerprints.repoTrustDoctorFingerprint` |

Secret-like evidence values must not be written to SARIF. Evidence messages should remain redacted and should avoid embedding raw secret material.

## Consequences

SARIF implementation is deferred until the fingerprint contract has stayed stable through more report and analyzer changes. Deferring avoids creating code-scanning alerts that churn because fingerprints or rule metadata are still moving.

When SARIF output is added, tests should cover deterministic JSON, location mapping, partial fingerprint mapping, and secret-safe evidence handling.
