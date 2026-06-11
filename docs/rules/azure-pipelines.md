# Azure Pipelines Rules

## TRUST-AZP001: Azure Pipeline Script Uses Untrusted Variable Expansion

- Category: CiCd
- Default severity: High
- Default confidence: Medium

Detects PR-controlled Azure variables (`$(System.PullRequest.SourceBranch)`, `$(Build.SourceBranch)`) interpolated in script steps.

Why it matters: these variables can be controlled by PR authors in `pull_request` triggers, potentially enabling injection.

Recommendation: avoid interpolating PR-controlled variables in script blocks. Use environment variables or template expressions instead.

## TRUST-AZP002: Azure Pipeline Checkout Persists Credentials

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects `checkout: self` with `persistCredentials: true`.

Why it matters: persisted credentials allow later steps to use repository write access, increasing the risk from compromised steps.

Recommendation: set `persistCredentials: false` unless later steps truly need repository write credentials.

## TRUST-AZP003: Azure Pipeline Container Image Uses Latest or No Tag

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects container or service images using `:latest` or no tag.

Why it matters: unpinned images change over time and make CI runs non-reproducible.

Recommendation: pin container images to specific versions or digests.

## TRUST-AZP004: Azure Pipeline Uses Self-Hosted Pool

- Category: CiCd
- Default severity: Low
- Default confidence: Medium

Detects self-hosted agent pools (without `vmImage`).

Why it matters: self-hosted agents may retain state across runs and require additional hardening.

Recommendation: isolate agents, rotate tokens, and limit workspace reuse.

## TRUST-AZP005: Azure Pipeline Publishes Broad Artifact Path

- Category: CiCd
- Default severity: Low
- Default confidence: Medium

Detects publish artifact tasks with overly broad paths (`.`, `./`, `$(System.DefaultWorkingDirectory)`).

Why it matters: publishing the entire workspace may leak secrets, sources, or intermediate artifacts.

Recommendation: narrow artifact publish paths to specific build output directories.
