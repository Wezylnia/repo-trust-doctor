# GitHub Actions Rules

## TRUST-GHA001: Workflow Permissions Are Not Declared

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects workflow files without an explicit `permissions` key.

Why it matters: implicit default permissions can be broader than a workflow needs.

Recommendation: declare least-privilege workflow permissions explicitly.

## TRUST-GHA002: Workflow Uses `permissions: write-all`

- Category: CI/CD
- Default severity: High
- Default confidence: High

Detects workflows that grant write access to all available scopes.

Why it matters: compromised jobs or actions may gain broad repository write access.

Recommendation: replace `write-all` with the narrowest permissions required by each job.

## TRUST-GHA003: Workflow Uses `pull_request_target`

- Category: CI/CD
- Default severity: High
- Default confidence: High

Detects workflows triggered by `pull_request_target`.

Why it matters: this trigger can run with elevated repository context and can be dangerous when combined with untrusted pull request code.

Recommendation: review usage carefully and avoid running untrusted pull request code with repository privileges.

## TRUST-GHA004: Workflow Pipes Downloaded Scripts Into a Shell

- Category: CI/CD
- Default severity: High
- Default confidence: High

Detects `curl | bash`, `curl | sh`, `wget | bash`, or `wget | sh` patterns.

Why it matters: remote scripts can change without a repository change and may execute unexpected code.

Recommendation: download scripts separately, verify integrity, and avoid piping remote content directly into a shell.

## TRUST-GHA005: Third-Party Action Is Not Pinned by SHA

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects `uses: owner/action@tag` references that are not pinned to a full commit SHA.

Why it matters: tags can move or be compromised, causing workflows to execute different code without a repository change.

Recommendation: pin third-party GitHub Actions to a full commit SHA.

## TRUST-GHA006: Workflow Uses Self-Hosted Runner

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects workflows specifying `runs-on: self-hosted`, lists containing `self-hosted`, or list elements matching `self-hosted`.

Why it matters: self-hosted runners run on user-owned infrastructure. If untrusted pull request code is executed on a self-hosted runner, it can access the environment, secrets, or internal network.

Recommendation: ensure self-hosted runners are isolated and do not run untrusted pull request code.
