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

Static analyzer implementation files suppress rule-vocabulary matches such as `Secret`, `Permission`, or regex helper names so analyzer rule text is not treated as application-critical code. Dangerous APIs such as command execution and unsafe deserialization are still reported.

Tooling and automation paths such as `.github/`, `build/`, `scripts/`, and `tools/` are retained in the criticality artifact, but they are not allowed to fill the general security-sensitive, large-critical-file, or broad-exception finding lists. Dangerous API findings such as command execution and unsafe deserialization still apply to those files.

Source files under common `tests`, `test`, `testdata`, `testassets`, `docs`, `doc`, `documentation`, `guides`, `changelogs`, `examples`, `samples`, `fixtures`, `mock`, `mocks`, `_mock`, `artifacts`, `integration-test`, `intTest`, `smoke-test`, `dockerTest`, `testFixtures`, `generated`, `gen`, `perf`, benchmark, project template, item template, and `playground` paths are skipped for criticality findings so example, generated, benchmark, template, and fixture code is not treated as production-critical code. Vendored/static library paths such as `vendor`, `third_party`, `external`, `wwwroot/lib`, `node_modules`, and bundled jQuery are also skipped.

On very large repositories, criticality analysis processes a deterministic subset after low-signal filtering and returns `CompletedWithWarnings` instead of timing out. The report metrics include source-file count, analyzed-file count, and whether the analyzer was truncated.

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

Noise control: handlers that immediately rethrow, wrap the exception into a domain-specific failure, log with exception context, or explicitly fail a module command are treated as bounded diagnostic boundaries instead of hidden failures.

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

A critical source file uses high-risk deserialization APIs such as `BinaryFormatter`, `TypeNameHandling`, `new ObjectInputStream(...)`, Python `pickle.load`, or `yaml.unsafe_load`. Simple Java serialization imports, `Serializable` marker interfaces, and custom `readObject(...)` hooks are not enough to trigger this high-severity rule.

Recommendation: use safe deserialization methods, restrict allowed types, and validate deserialized input.

### `TRUST-CODE015` - Command execution in critical code

- Category: `Codebase`
- Default severity: `High`
- Default confidence: `Medium`

A critical source file invokes operating-system command execution APIs such as `Process.Start(...)`, `Runtime.exec(...)`, `ProcessBuilder(...)`, Python `subprocess.run(...)`/`Popen(...)`, `os.system(...)`, Node `child_process.exec(...)`/`spawn(...)`, `execSync(...)`, `spawnSync(...)`, Rust `Command::new(...)`, or `popen(...)`. Imports, comments, and generic “command line” wording are not enough to trigger this rule.

When the same signal appears under build, CI, scripts, or other tooling paths, the finding is still reported because tooling often runs with repository or release credentials, but the title and severity are softened to `Command execution in build or tooling code` with `Medium` severity.

Recommendation: avoid shell execution for untrusted input. Prefer purpose-built APIs, strict allowlists, and explicit argument passing that does not interpolate user-controlled strings into a shell command.

### `TRUST-CODE016` - Dynamic code evaluation in critical code

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

A critical source file dynamically evaluates code at runtime, for example with JavaScript/TypeScript `eval(...)` or `new Function(...)`, or Python/Ruby `eval(...)`. This is separate from `TRUST-CODE015`: dynamic code evaluation is risky, but it is not reported as operating-system command execution. Domain-specific method names such as Go `Eval(...)` and safe helpers such as Python `ast.literal_eval(...)` are not enough to trigger this rule.

Recommendation: avoid eval-style APIs for untrusted input and keep any intentional dynamic module loading tightly bounded.

### `TRUST-CODE017` - Java serialization hook in critical code

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

A critical Java source file defines a custom `readObject(...)` serialization hook. This is tracked separately from `TRUST-CODE014` because many framework classes use the hook only to restore transient state after default Java serialization.

Recommendation: review custom serialization hooks and validate any data restored during deserialization.

## Public API

### `TRUST-CODE008` - Public API baseline is missing

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `Medium`

Public API symbols were detected, but no baseline file was found for compatibility comparison.

The analyzer extracts a conservative multi-language public API surface from C#, TypeScript/JavaScript, Python, Java, Go, and Rust source files. On very large repositories, it processes a deterministic subset after low-signal filtering and reports truncation in metrics and warnings instead of timing out.

Baseline paths checked:

- `.repo-trust/public-api-baseline.txt`
- `docs/public-api-baseline.txt`
- `public-api-baseline.txt`

Recommendation: commit a reviewed public API baseline when the repository exposes a library or reusable package.

### `TRUST-CODE009` - Public API differs from baseline

- Category: `Codebase`
- Default severity: `Medium`
- Default confidence: `Medium`

The current public API symbol list differs from the committed baseline. This is a review signal; it is not a claim that every change is breaking.

Recommendation: review added and removed symbols before release and update the baseline only after compatibility impact is understood.

## Central Files

### `TRUST-CODE010` - Highly central file detected

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `Medium`

A source file is imported by many other files, making it a high-impact change target.

Type-only TypeScript imports such as `import type { Foo } from './types'` are ignored because they do not create runtime coupling.

On very large repositories, import graph analysis processes a deterministic subset after low-signal filtering and returns `CompletedWithWarnings` instead of timing out. The report metrics include total candidate files, analyzed files, and truncation status.

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

On very large repositories, route detection processes a deterministic subset of candidate framework files after low-signal filtering and returns `CompletedWithWarnings` instead of timing out.

Express middleware-only `app.use(middleware)` calls are not treated as endpoints; `app.use('/path', ...)` remains route evidence. Route-like text inside string literals or comments is ignored. Django route detection is limited to `urls.py` or `/urls/` configuration paths and line-anchored URL pattern entries, so Python helpers such as `Path(...)` or `url(...)` are not treated as Django routes. Django `admin_view`/permission wrappers count as auth hints, and Django's own `contrib` and `conf/urls` router internals are skipped. Spring annotation declaration files, endpoint annotation internals, and Spring framework source paths under `org/springframework` are not treated as application endpoints. Source files under common test, generated, benchmark, template, documentation, sample, fixture, analyzer implementation, and playground paths are skipped for route findings.

Recommendation: add authentication middleware or auth annotations to HTTP endpoints, or document why public access is intentional.

### `TRUST-CODE013` - Framework route detected

- Category: `Codebase`
- Default severity: `Info`
- Default confidence: `High`

An HTTP route or controller endpoint was detected using a common web framework.

Route detection uses framework-specific context to reduce false positives from middleware registration, test fixtures, and non-route helper calls.

Recommendation: review HTTP endpoints for proper authentication, authorization, input validation, and rate limiting.
