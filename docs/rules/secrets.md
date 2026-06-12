# Secret Rules

## TRUST-SECRET001: Sensitive-Looking File Is Committed

- Category: Security
- Default severity: High
- Default confidence: High

Detects committed files such as `.env`, `.env.production`, `id_rsa`, `.pem`, and `.key`.

Why it matters: these files often contain secrets, credentials, or private keys.

Recommendation: manually verify the file, rotate exposed secrets if confirmed, and remove the secret from repository history.

## TRUST-SECRET002: Possible Private Key Marker Found

- Category: Security
- Default severity: Critical
- Default confidence: High

Detects private key block markers.

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

## False-Positive Suppression

To avoid noise in automated testing and documentation, the secret scanner ignores internal secret pattern matches and sensitive-looking example filenames (such as `.env`) within files residing in the following paths:
- `tests/Fixtures/`
- `tests/`
- `__tests__/`
- `fixtures/`
- `examples/`
- `playground/`
- `testdata/`
- `docs/examples/`

Markdown files under `docs/` also suppress JWT-token examples, because many security tutorials include sample JWTs. Note that files under these paths are still checked for general repository metadata or container settings where appropriate, but secret rules will not fire.

## Generic API Key Filtering (TRUST-SECRET012)

TRUST-SECRET012 applies additional filtering in v1.6 to reduce false positives:

- Skips values containing variable references: `${...}`, `${{ ... }}`, `%...%`.
- Skips values containing placeholder keywords: `example`, `dummy`, `changeme`, `sample`, `test`, `xxxx`, `abc123`, `replace`.
- Skips values shorter than 20 alphanumeric characters after stripping quotes.
- Skips values without at least one uppercase letter, one lowercase letter, and one digit.
