# CircleCI Rules

## TRUST-CIRCLE001: CircleCI Orb Version Is Not Pinned

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects orb declarations without a pinned version (e.g., `circleci/node` instead of `circleci/node@5.1.0`) or using floating versions (`@volatile`, `@dev`, `@latest`).

Why it matters: unpinned orbs can change without notice and introduce unexpected behavior or vulnerabilities.

Recommendation: pin orb versions to specific releases using the `@x.y.z` notation.

## TRUST-CIRCLE002: CircleCI Docker Executor Image Uses Latest or No Tag

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects Docker executor images using `:latest` or no tag.

Why it matters: unpinned images change over time and make builds non-reproducible.

Recommendation: pin Docker images to specific versions or digests.

## TRUST-CIRCLE003: CircleCI Workspace Persist Stores Repository Root

- Category: CiCd
- Default severity: Low
- Default confidence: Medium

Detects `persist_to_workspace` with `root: .` or `root: ~/project`.

Why it matters: persisting the entire repository root can leak sensitive files between jobs.

Recommendation: persist only build output directories.

## TRUST-CIRCLE004: CircleCI Inline Secret-Looking Environment Variable

- Category: Security
- Default severity: High
- Default confidence: Medium

Detects literal secret-looking values (keys containing TOKEN, SECRET, PASSWORD, PRIVATE_KEY, API_KEY) in CircleCI `environment:` blocks.

Why it matters: plaintext secrets in CI config may be exposed to anyone with repository access.

Recommendation: use CircleCI contexts or external secret management. Evidence is redacted.

## TRUST-CIRCLE005: CircleCI Remote Docker Enabled Without Explicit Version

- Category: CiCd
- Default severity: Low
- Default confidence: Medium

Detects `setup_remote_docker` without a `version:` declaration nearby.

Why it matters: using remote Docker without an explicit version may silently change behavior when CircleCI updates defaults.

Recommendation: specify an explicit Docker version with `setup_remote_docker`.
