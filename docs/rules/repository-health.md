# Repository Health Rules

## TRUST-REPO001: README Is Missing

- Category: Repository Health
- Default severity: Medium
- Default confidence: High

Detects repositories without a root `README.md` or `README` file.

Why it matters: users may not understand the project purpose, installation steps, or basic usage.

Recommendation: add a README that explains the project purpose, installation, and basic usage.

## TRUST-REPO002: LICENSE Is Missing

- Category: Repository Health
- Default severity: High
- Default confidence: High

Detects repositories without a root `LICENSE` or `LICENSE.md` file.

Why it matters: users may not know whether they are allowed to use, modify, or redistribute the project.

Recommendation: add a license file with the intended open-source license.

## TRUST-REPO003: SECURITY.md Is Missing

- Category: Repository Health
- Default severity: Low
- Default confidence: High

Detects repositories without `SECURITY.md` at the root or under `.github/`.

Why it matters: users and researchers may not know how to report vulnerabilities responsibly.

Recommendation: add `SECURITY.md` with vulnerability reporting guidance.

## TRUST-REPO004: CONTRIBUTING.md Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without contribution guidance.

Why it matters: contributors may not know expected development, testing, or review practices.

Recommendation: add `CONTRIBUTING.md` when the project accepts external contribution.

## TRUST-REPO005: CODE_OF_CONDUCT.md Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without a code of conduct.

Why it matters: community expectations may be unclear.

Recommendation: add a code of conduct for community-facing projects.

## TRUST-REPO006: CODEOWNERS Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without `CODEOWNERS`.

Why it matters: ownership and review responsibility may be unclear.

Recommendation: add `CODEOWNERS` when review ownership should be explicit.

## TRUST-REPO007: Issue Template Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without an issue template.

Why it matters: maintainers may receive incomplete reports that are difficult to triage.

Recommendation: add issue templates under `.github/ISSUE_TEMPLATE`.

## TRUST-REPO008: Pull Request Template Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without a pull request template.

Why it matters: contributors may omit testing notes, risk context, or implementation details.

Recommendation: add `.github/PULL_REQUEST_TEMPLATE.md`.

## TRUST-REPO009: CHANGELOG Is Missing

- Category: Repository Health
- Default severity: Info
- Default confidence: High

Detects repositories without `CHANGELOG.md`, `CHANGELOG`, `HISTORY.md`, or `RELEASES.md` at the root.

Why it matters: users and consumers need a clear log of release-to-release changes, fixes, and deprecations to safely perform updates.

Recommendation: add a changelog to document user-facing changes in each release.

## TRUST-REPO010: README Lacks Installation Guidance

- Category: Repository Health
- Default severity: Low
- Default confidence: Medium

Detects if the README exists but lacks common installation keywords.

Why it matters: users may have trouble setting up, installing, or building the project.

Recommendation: add installation instructions or a getting started section to the README.

## TRUST-REPO011: README Lacks Usage Guidance

- Category: Repository Health
- Default severity: Low
- Default confidence: Medium

Detects if the README exists but lacks common usage keywords or examples.

Why it matters: users may not know how to run or import the project.

Recommendation: add usage instructions or examples to the README.
