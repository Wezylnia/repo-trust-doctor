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

Noise control: when the same workflow also checks out pull request code or uses secrets in a risky run context, the analyzer reports the more specific `TRUST-GHA015` finding instead of also emitting this general trigger finding.

## TRUST-GHA004: Workflow Pipes Downloaded Scripts Into a Shell

- Category: CI/CD
- Default severity: High
- Default confidence: High

Detects `curl | bash`, `curl | sh`, `wget | bash`, or `wget | sh` patterns.

Why it matters: remote scripts can change without a repository change and may execute unexpected code.

Recommendation: download scripts separately, verify integrity, and avoid piping remote content directly into a shell.

## TRUST-GHA005: External Action Is Not Pinned by SHA

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects external `uses: owner/action@tag` references that are not pinned to a full commit SHA. Local repository actions such as `uses: ./path/to/action` are ignored. Repeated uses of the same `action@version` are grouped into one finding with sample locations to keep large workflow suites readable.

Why it matters: tags can move or be compromised, causing workflows to execute different code without a repository change.

Recommendation: pin external GitHub Actions to a full commit SHA.

## TRUST-GHA006: Workflow Uses Self-Hosted Runner

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects workflows specifying `runs-on: self-hosted`, lists containing `self-hosted`, or list elements matching `self-hosted`.

Why it matters: self-hosted runners run on user-owned infrastructure. If untrusted pull request code is executed on a self-hosted runner, it can access the environment, secrets, or internal network.

Recommendation: ensure self-hosted runners are isolated and do not run untrusted pull request code.

## TRUST-GHA007: Checkout May Persist Credentials

- Category: CI/CD
- Default severity: Low
- Default confidence: Medium

Detects `uses: actions/checkout@...` steps that do not specify `persist-credentials: false` within the same checkout step. Repeated checkout steps are grouped into one low-severity finding with sample locations.

Why it matters: by default, `actions/checkout` persists the GitHub token in the local git configuration. If subsequent steps run untrusted code or upload artifacts, they might read or expose this token.

Recommendation: set `persist-credentials: false` when checkout is only used for building or testing.

## TRUST-GHA008: Workflow May Interpolate GitHub Event Data in Shell

- Category: CI/CD
- Default severity: High
- Default confidence: Medium

Detects `run:` steps containing inline shell interpolation of `github.event.*`, `github.head_ref`, or `github.ref_name`.

Why it matters: if an attacker modifies fields like a pull request title, issue description, or git branch name, direct interpolation within a shell script run block can execute arbitrary shell commands inside the workflow runner.

Recommendation: avoid direct inline shell interpolation of event data. Pass event data as environment variables instead, and read them using shell environment variables.

## TRUST-GHA009: Release Workflow May Publish Without Test Dependency

- Category: CI/CD
- Default severity: High
- Default confidence: Medium

Detects workflows that appear to publish packages, Docker images, or GitHub releases without a visible `needs:` dependency on a test or CI job.

Why it matters: release jobs that do not depend on tests may publish unverified artifacts or packages.

Recommendation: make release or publish jobs depend on a test or CI job before publishing artifacts or packages.

## TRUST-GHA010: Workflow Uploads Overly Broad Artifact Path

- Category: CI/CD
- Default severity: Medium
- Default confidence: Medium

Detects `actions/upload-artifact` steps that upload very broad paths such as `.` or `**/*`.

Why it matters: broad artifact uploads may include source files, generated temporary files, logs, or sensitive files that were not intended to leave the runner.

Recommendation: upload only specific build outputs and avoid broad artifact paths.

## TRUST-GHA011: Workflow Does Not Restrict GITHUB_TOKEN Scope

- Category: CI/CD
- Default severity: Medium
- Default confidence: High

Detects top-level workflow `permissions:` blocks that grant write access instead of keeping the workflow default read-only and moving write scopes to the specific job that needs them.

Why it matters: without explicit job-level permission restrictions, the token may carry broader access than needed. If a job is compromised through a supply-chain or injection vector, the token may allow wider repository actions.

Recommendation: keep top-level workflow permissions read-only or empty, then set per-job permissions to the minimum required scope.

## TRUST-GHA013: Workflow May Contain Hardcoded Secret in Step Env

- Category: CI/CD
- Default severity: High
- Default confidence: Medium

Detects step-level `env:` blocks that set environment variables with secret-like names (PASSWORD, TOKEN, SECRET, API_KEY, AUTH_TOKEN) with inline values.

Why it matters: hardcoded values in workflow files are visible to anyone with read access to the repository. Secret-like values should be stored in GitHub Secrets.

Recommendation: use `${{ secrets.SECRET_NAME }}` instead of inline values for credentials and tokens.

## TRUST-GHA014: Workflow May Interpolate Matrix Values in Shell

- Category: CI/CD
- Default severity: High
- Default confidence: Medium

Detects `run:` steps containing inline shell interpolation of `${{ matrix.* }}` values.

Why it matters: matrix values may be controlled through workflow triggers or pull request data. Direct interpolation within a shell script run block can lead to command injection if the matrix values are not sanitized.

Recommendation: pass matrix values as environment variables instead of interpolating them directly in shell commands.
