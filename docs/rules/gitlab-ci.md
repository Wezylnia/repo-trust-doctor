# GitLab CI Rules

## TRUST-GLCI001: GitLab CI Uses Remote Includes

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects `include: remote:` in `.gitlab-ci.yml`.

Why it matters: remote includes may change without repository changes, introducing supply-chain risk.

Recommendation: review the content and provenance of all remote includes. Pin to trusted revisions or mirror them in-repo.

## TRUST-GLCI002: GitLab CI Dynamically Executes CI Variables

- Category: CiCd
- Default severity: High
- Default confidence: Medium

Detects script lines that pass CI/CD variables to dynamic execution sinks such
as `eval`, `sh -c`, `bash -c`, or PowerShell command strings. Ordinary variable
use such as `echo "$CI_ENVIRONMENT_URL"` is not reported.

Why it matters: dynamic shell execution interprets variable content as code,
which can create injection vulnerabilities when the value is attacker
controlled.

Recommendation: avoid dynamic shell execution and pass validated values as
ordinary command arguments.

The analyzer follows explicit, non-glob `include: local:` paths within the
repository so security checks also cover split pipeline definitions.

## TRUST-GLCI003: GitLab CI Uses Latest Image Tag

- Category: CiCd
- Default severity: Medium
- Default confidence: High

Detects job images or services that use the `:latest` tag.

Why it matters: `latest` changes over time and can make CI runs non-reproducible.

Recommendation: pin container images to specific versions or digests.

## TRUST-GLCI004: GitLab CI Uses Deprecated `only`/`except`

- Category: CiCd
- Default severity: Low
- Default confidence: High

Detects deprecated `only:` and `except:` keywords.

Why it matters: `only`/`except` are deprecated in favor of `rules:` and may be removed in future GitLab versions.

Recommendation: migrate to the `rules:` syntax for better control and forward compatibility.

## TRUST-GLCI005: GitLab CI Uses Privileged Docker-in-Docker

- Category: CiCd
- Default severity: High
- Default confidence: Medium

Detects Docker-in-Docker (`docker:dind`) services or privileged mode (unset `DOCKER_TLS_CERTDIR`, `privileged: true`).

Why it matters: privileged containers can escape isolation. Docker-in-Docker in untrusted pipelines can compromise the runner and neighboring jobs.

Recommendation: prefer rootless builders (Kaniko, BuildKit with least privilege), or isolate DinD jobs on dedicated, ephemeral runners.

## TRUST-GLCI006: GitLab CI Cache Uses Broad Path

- Category: CiCd
- Default severity: Medium
- Default confidence: Medium

Detects overly broad cache paths such as `.`, `./*`, or `*`.

Why it matters: broad cache paths can cause unintended cache pollution, increase cache size, and potentially expose sensitive files across jobs.

Recommendation: narrow cache paths to specific build output directories (e.g., `target/`, `node_modules/`, `.gradle/`).
