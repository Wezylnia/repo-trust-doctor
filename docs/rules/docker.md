# Docker Rules

## TRUST-DOCKER001: Dockerfile Exists but `.dockerignore` Is Missing

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects repositories with Dockerfiles but no root `.dockerignore`.

Why it matters: large or sensitive files may be copied into the Docker build context unintentionally.

Recommendation: add `.dockerignore` to keep unnecessary and sensitive files out of the build context.

## TRUST-DOCKER002: Docker Base Image Uses `latest` Tag

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `FROM image:latest`.

Why it matters: `latest` changes over time and can make builds non-reproducible.

Recommendation: pin base images to specific versions, and use digests for stronger reproducibility where practical.

## TRUST-DOCKER003: Dockerfile Does Not Declare a Non-Root USER

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects Dockerfiles without a `USER` instruction.

Why it matters: containers may run as root by default, increasing impact if the application is compromised.

Recommendation: create and switch to a non-root user for runtime stages.

## TRUST-DOCKER004: Dockerfile Does Not Declare HEALTHCHECK

- Category: Containers
- Default severity: Low
- Default confidence: High

Detects Dockerfiles without `HEALTHCHECK`.

Why it matters: orchestration systems may have less reliable signal for detecting unhealthy containers.

Recommendation: add an appropriate `HEALTHCHECK` for long-running services.
