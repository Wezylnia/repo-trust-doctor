# ADR 0004: SARIF Output Design

Status: Accepted

## Context

SARIF is useful because GitHub code scanning and other security tools can ingest structured analysis results, show findings inline with source locations, track alerts across runs, and suppress duplicate noise when stable fingerprints are available.

Repository Trust Doctor emits JSON, Markdown, and SARIF reports. Those reports already include structured rule IDs, categories, severity, confidence, evidence, recommendations, and stable finding fingerprints. SARIF output builds on that model rather than becoming a separate analyzer output path.

## Decision

SARIF output is produced by the reporting layer from `RepositoryScan` and `Finding` models.

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

SARIF output is implemented in the reporting layer and shares the CLI overwrite protections used by JSON and Markdown reports.

Tests cover deterministic rule/result output, location mapping, partial fingerprint mapping, and secret-safe evidence handling.
