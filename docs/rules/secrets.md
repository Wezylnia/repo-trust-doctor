# Secret Rules

## TRUST-SECRET001: Sensitive-Looking File Is Committed

- Category: Security
- Default severity: High
- Default confidence: High

Detects committed files such as `.env`, `.env.local`, `.env.production`, `.npmrc`, `.pypirc`, `id_rsa`, private-key-like `.pem`, and `.key`.

Why it matters: these files often contain secrets, credentials, or private keys.

Plain public certificate `.pem` files containing `-----BEGIN CERTIFICATE-----` without a private-key marker are not reported as sensitive files. Readable sensitive files are still scanned for concrete token evidence after the file-level finding is created, so reports can include redacted registry tokens from files such as `.npmrc` or `.pypirc`.

Recommendation: manually verify the file, rotate exposed secrets if confirmed, and remove the secret from repository history.

## TRUST-SECRET002: Possible Private Key Marker Found

- Category: Security
- Default severity: Critical
- Default confidence: High

Detects private key block markers. Complete private-key blocks are reported even when they appear inside source files; single-line marker constants in source code are suppressed when no matching key block exists.

Why it matters: committed private keys can allow unauthorized access to systems or services.

Recommendation: rotate the key immediately if confirmed and remove it from repository history.

## TRUST-SECRET003: Possible GitHub Token Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects GitHub token-like values.

Why it matters: exposed tokens may allow repository or organization access depending on token scope.

Recommendation: manually verify, revoke or rotate the token if confirmed, and avoid exposing full secret values in reports.

## TRUST-SECRET004: Possible AWS Access Key Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects AWS access key-like values.

Why it matters: exposed cloud credentials can lead to unauthorized resource access and cost impact.

Recommendation: manually verify, rotate credentials if confirmed, and review cloud audit logs.

## TRUST-SECRET005: Possible Database Connection String Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects database connection string-like values with user and password fields.

Why it matters: exposed database credentials may allow data access or modification.

Recommendation: manually verify, rotate credentials if confirmed, and move secrets to a secure secret store.

## TRUST-SECRET006: Possible Slack Webhook Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects Slack webhook-like URLs.

Why it matters: exposed Slack webhooks allow posting messages to Slack channels, which could be abused for spam, phishing, or information disclosure.

Recommendation: manually verify the finding, revoke or rotate the webhook URL if confirmed, and remove it from repository history.

## TRUST-SECRET007: Possible Discord Webhook Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects Discord webhook-like URLs.

Why it matters: exposed Discord webhooks allow posting messages or executing actions in Discord channels, which could be abused.

Recommendation: manually verify the finding, revoke or rotate the webhook URL if confirmed, and remove it from repository history.

## TRUST-SECRET009: Possible GCP Service Account Key Found

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects Google Cloud service account JSON keys when the file includes the `service_account` type, a service account email, and an embedded private key marker. A bare `"type": "service_account"` example is not enough to trigger this rule.

Why it matters: exposed service account keys can grant access to cloud resources depending on IAM scope.

Recommendation: revoke or rotate the service account key if confirmed, audit recent key usage, and move deployment credentials into a managed secret store.

## Candidate Files And False-Positive Suppression

The secret scanner reads likely text/config/source candidates rather than every repository file. It always considers sensitive filenames and key/certificate extensions, registry config files such as `.npmrc` and `.pypirc`, plus common source and configuration formats such as `.cs`, `.js`, `.ts`, `.py`, `.go`, `.java`, `.php`, `.rb`, `.yml`, `.yaml`, `.json`, `.toml`, `.properties`, `.tf`, `.sh`, `.ps1`, `.cmd`, `.gradle`, and `.txt`.

Large repositories are scanned in priority order. Sensitive filenames and credential config files such as `.npmrc` and `.pypirc` are analyzed before general configuration and source files. General configuration and source-file content scanning are bounded for the quick scan; the default source-content budget is 800 files, while sensitive filenames and credential config files remain outside that low-priority source budget. If either budget is reached, the analyzer returns `CompletedWithWarnings` with metrics such as `secret.configuration.content.scanned.count`, `secret.configuration.content.skipped.count`, `secret.source.content.scanned.count`, and `secret.source.content.skipped.count`. This keeps broad repository scans responsive while preserving the highest-signal secret locations.

To avoid noise in automated testing, vendored code, generated files, and documentation, the secret scanner ignores internal secret pattern matches and sensitive-looking example filenames (such as `.env`) within files residing in low-signal paths including:
- `tests/Fixtures/`
- `tests/`
- `test/`
- `src/test/`
- `__tests__/`
- `fixtures/`
- `mock/`
- `mocks/`
- `_mock/`
- `examples/`
- `samples/`
- `playground/`
- `testdata/`
- `testassets/`
- `testcertificates/`
- `test_creds/`
- `test_credentials/`
- `test-certs/`
- `test_certs/`
- path segments beginning with `tests_` or ending with `_tests`
- `integration-test/`
- `smoke-test/`
- `dockerTest/`
- `testFixtures/`
- `src/javaRestTest/`
- `src/yamlRestTest/`
- `rest-tests/`
- `docs/examples/`
- `doc/`
- `documentation/`
- `guides/`
- `changelogs/`
- `generated/`
- `artifacts/`
- `vendor/`
- `third_party/`
- `external/`
- `node_modules/`

Markdown files under `docs` also suppress JWT-token examples, because many security tutorials include sample JWTs. Plain documentation files are still scanned for concrete secret content. Private-key examples are suppressed only when the block is clearly placeholder or lacks real-looking base64 key material; documentation files containing real-looking private key blocks are reported. Sensitive-looking certificate or environment filenames under documentation paths are also suppressed to avoid flagging committed tutorial artifacts such as sample `.p12` files. `.npmrc` and `.pypirc` are scanned for real registry token patterns but do not trigger `TRUST-SECRET001` merely because the config file exists.

## Generic API Key Filtering (TRUST-SECRET012)

TRUST-SECRET012 applies additional filtering in v1.6 to reduce false positives:

- Skips values containing variable references: `${...}`, `${{ ... }}`, `%...%`.
- Skips values containing placeholder keywords: `example`, `dummy`, `changeme`, `sample`, `test`, `xxxx`, `abc123`, `replace`.
- Skips values shorter than 20 alphanumeric characters after stripping quotes.
- Skips values without at least one uppercase letter, one lowercase letter, and one digit.
