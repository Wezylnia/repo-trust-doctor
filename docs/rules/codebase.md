# Codebase Rules

Codebase rules run only in `--depth deep`. They are static or imported-evidence checks: the scanner does not execute repository code, install dependencies, run tests, run builds, or generate coverage by default.

## Coverage Import

### `TRUST-CODE001` - Coverage report was not found

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `High`

No supported coverage report was found. Repository Trust Doctor treats coverage as unknown rather than running the repository's test suite.

Supported imported coverage formats:

- Cobertura XML: `coverage.xml`, `cobertura.xml`, `*.cobertura.xml`
- lcov: `lcov.info`, `coverage.info`

Recommendation: publish Cobertura XML or lcov artifacts from CI and make them available to deep scans.

### `TRUST-CODE002` - Imported coverage is below the recommended baseline

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

An imported coverage report has line coverage below the recommended baseline.

Recommendation: improve tests around changed and critical code paths, or document why the baseline is intentionally lower.

### `TRUST-CODE003` - Coverage report could not be parsed

- Category: `Codebase`
- Default severity: `Low`
- Default confidence: `High`

A supported coverage file was found but could not be parsed safely. XML parsing disables DTD processing and external resource resolution.

Recommendation: regenerate the coverage artifact in Cobertura XML or lcov format and ensure it is not truncated.

## Critical Code

### `TRUST-CODE004` - Security-sensitive code area was detected

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

A source file appears to contain security-sensitive or operationally critical logic. Signals include authentication, authorization, payments, database access, file operations, network calls, cryptography, secrets, and credentials.

Recommendation: prioritize review and tests for these files.

### `TRUST-CODE005` - Large critical source file was detected

- Category: `Codebase`
- Default severity: `Low`
- Default confidence: `Medium`

A critical source file is large enough to make review and change isolation harder.

Recommendation: split large critical files or add targeted tests before risky changes.

### `TRUST-CODE006` - Broad exception handling in critical code

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

A critical source file uses broad exception handling such as `catch (Exception)` or `except Exception`.

Recommendation: catch specific exception types and preserve diagnostic context.

### `TRUST-CODE007` - Critical code has low or missing coverage

- Category: `Codebase`
- Default severity: `High`
- Default confidence: `Medium`

An imported coverage report exists, and a critical source file has low line coverage or is absent from the report.

Recommendation: add targeted unit or integration tests for the critical code path before relying on this repository in production.

### `TRUST-CODE014` - Deserialization in critical code

- Category: `Codebase`
- Default severity: `High`
- Default confidence: `Medium`

A critical source file uses deserialization APIs (like BinaryFormatter, pickle, yaml, xmlserializer) that are known vectors for remote code execution.

Recommendation: use safe deserialization methods, restrict allowed types, and validate deserialized input.

## Public API

### `TRUST-CODE008` - Public API baseline is missing

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `Medium`

Public .NET API symbols were detected, but no baseline file was found for compatibility comparison.

Baseline paths checked:

- `.repo-trust/public-api-baseline.txt`
- `docs/public-api-baseline.txt`
- `public-api-baseline.txt`

Recommendation: commit a reviewed public API baseline when the repository exposes a library or reusable package.

### `TRUST-CODE009` - Public API differs from baseline

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

The current public .NET API symbol list differs from the committed baseline. This is a review signal; it is not a claim that every change is breaking.

Recommendation: review added and removed symbols before release and update the baseline only after compatibility impact is understood.

## Central Files

### `TRUST-CODE010` - Highly central file detected

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `Medium`

A source file is imported by many other files, making it a high-impact change target.

Recommendation: ensure highly central files have thorough tests and careful review gates.

### `TRUST-CODE011` - Central file has low or missing coverage

- Category: `Codebase`
- Default severity: `High`
- Default confidence: `Medium`

A highly central file has low or missing test coverage, amplifying the blast radius of defects.

Recommendation: add targeted tests for central files to reduce risk of cascading breakage.

## Framework Routes

### `TRUST-CODE012` - HTTP endpoint without authentication annotation

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Low`

An HTTP route handler was detected without a visible authentication or authorization annotation.

Recommendation: add authentication middleware or auth annotations to HTTP endpoints, or document why public access is intentional.

### `TRUST-CODE013` - Framework route detected

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `High`

An HTTP route or controller endpoint was detected using a common web framework.

Recommendation: review HTTP endpoints for proper authentication, authorization, input validation, and rate limiting.
