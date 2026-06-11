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

## TRUST-DOCKER005: Dockerfile May Define Secret-Like ENV

- Category: Containers
- Default severity: High
- Default confidence: Medium

Detects `ENV` instructions in Dockerfiles that define values for secret-like keys (e.g. `PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`).

Why it matters: environment variables set in Dockerfiles persist in the image layers and can be retrieved by anyone with access to the image.

Recommendation: avoid defining secrets in ENV variables. Use Docker build secrets or pass secrets at runtime instead.

## TRUST-DOCKER006: Dockerfile Does Not Appear to Use Multi-Stage Build

- Category: Containers
- Default severity: Low
- Default confidence: Medium

Detects Dockerfiles that have exactly one `FROM` instruction.

Why it matters: single-stage builds often include build dependencies, compilers, and source code in the final image, increasing the image size and the attack surface.

Recommendation: use multi-stage builds to reduce image size and improve security by separating build dependencies from the runtime image.

## TRUST-DOCKER007: Dockerfile Copies Entire Context Before Dependency Restore

- Category: Containers
- Default severity: Low
- Default confidence: Medium

Detects `COPY . .` before common dependency restore or install commands.

Why it matters: copying the full source tree before restoring dependencies can invalidate the dependency cache on every source change and may increase accidental build-context exposure.

Recommendation: copy dependency manifest files first, restore dependencies, then copy the rest of the source.

## TRUST-DOCKER008: Dockerfile Separates `apt-get update` From Install

- Category: Containers
- Default severity: Low
- Default confidence: Medium

Detects `apt-get update` and `apt-get install` in separate `RUN` instructions.

Why it matters: separating package index updates from installs can create stale package index layers and less reproducible builds.

Recommendation: combine `apt-get update` and `apt-get install` in one `RUN` instruction and clean package lists in the same layer.

## TRUST-DOCKER009: Dockerfile Uses ADD Instead of COPY

- Category: Containers
- Default severity: Low
- Default confidence: High

Detects `ADD` instructions where the source is a local path rather than a URL or archive.

Why it matters: `ADD` has implicit behaviors such as tar extraction that `COPY` does not have. Using `COPY` for local file operations is more predictable and less likely to introduce unexpected behavior.

Recommendation: prefer `COPY` over `ADD` unless you specifically need tar extraction or URL fetching.

## TRUST-DOCKER010: Dockerfile Uses sudo

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `sudo` in `RUN` instructions.

Why it matters: Docker containers typically run as root by default, and `sudo` adds complexity without providing isolation. If a non-root USER is already set, sudo may indicate privilege escalation patterns.

Recommendation: remove sudo usage and run commands directly without privilege escalation.

## TRUST-DOCKER011: Dockerfile EXPOSE Uses Overly Broad Port Range

- Category: Containers
- Default severity: Low
- Default confidence: Medium

Detects `EXPOSE` instructions that specify a port range spanning more than 100 ports.

Why it matters: exposing large port ranges may indicate that the image is unnecessarily permissive. It is better to expose only the ports the application actually listens on.

Recommendation: expose only the specific ports your application needs.

## Docker Compose Rules

### TRUST-COMP001: Docker Compose service runs in privileged mode

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `privileged: true` on a Compose service.

Why it matters: privileged containers have almost full host capabilities and can escape isolation.

Recommendation: avoid privileged mode unless absolutely necessary. Drop specific capabilities instead.

### TRUST-COMP002: Docker Compose service uses host network mode

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `network_mode: host` on a Compose service.

Why it matters: host network mode bypasses container network isolation entirely.

Recommendation: use bridge networks instead of host mode.

### TRUST-COMP003: Docker Compose mounts host directory

- Category: Containers
- Default severity: Medium
- Default confidence: Medium

Detects host path volume mounts in Compose files.

Why it matters: host directory mounts can expose the host filesystem to the container.

Recommendation: prefer named volumes and review host path mounts.

### TRUST-COMP004: Docker Compose exposes broad port range

- Category: Containers
- Default severity: Low
- Default confidence: High

Detects port mappings bound to `0.0.0.0` (all interfaces).

Why it matters: binding to all interfaces exposes the service to potentially untrusted networks.

Recommendation: bind services to specific interfaces where possible.

### TRUST-COMP005: Docker Compose may define secrets in environment

- Category: Containers
- Default severity: High
- Default confidence: Medium

Detects secret-like environment variable keys (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`) with literal values in Compose files.

Why it matters: plaintext secrets in Compose files may be committed to version control.

Recommendation: use Docker secrets or external secret management.

### TRUST-COMP006: Docker Compose mounts Docker socket

- Category: Containers
- Default severity: Critical
- Default confidence: High

Detects volume mounts of `/var/run/docker.sock` or `/run/docker.sock`.

Why it matters: mounting the Docker socket grants high privilege over the host Docker daemon. A compromised container can control all containers on the host.

Recommendation: do not mount the Docker socket into application services. Use a dedicated isolated builder or tightly controlled automation.

### TRUST-COMP007: Docker Compose loads environment from .env-like file

- Category: Containers
- Default severity: Medium
- Default confidence: Medium

Detects `env_file:` entries pointing to `.env`, `.env.production`, `.env.prod`, `.env.local`, or files ending in `.secret`/`.secrets`.

Why it matters: environment files may contain secrets or sensitive configuration. Loading them into containers increases exposure risk.

Recommendation: review env_file entries and avoid loading production environment files into containers.

## Kubernetes Manifest Rules

### TRUST-K8S001: Kubernetes container runs in privileged mode

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `securityContext.privileged: true`.

Why it matters: privileged containers have almost full host capabilities and can escape isolation.

Recommendation: avoid privileged containers. Use specific Linux capabilities instead.

### TRUST-K8S002: Kubernetes pod shares host namespace

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `hostNetwork`, `hostPID`, or `hostIPC` set to true.

Why it matters: sharing host namespaces breaks container isolation and can expose the host to the container.

Recommendation: avoid sharing host namespaces unless absolutely necessary.

### TRUST-K8S003: Kubernetes container may run as root

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects missing `runAsNonRoot: true`.

Why it matters: containers running as root have full privileges inside the container and can escalate more easily.

Recommendation: set `securityContext.runAsNonRoot: true` and specify a non-root user.

### TRUST-K8S004: Kubernetes container has writable root filesystem

- Category: Containers
- Default severity: Low
- Default confidence: High

Detects missing `readOnlyRootFilesystem: true`.

Why it matters: a writable root filesystem allows attackers to modify binaries and configurations after compromise.

Recommendation: set `securityContext.readOnlyRootFilesystem: true` for immutable infrastructure.

### TRUST-K8S005: Kubernetes Secret manifest in repository

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `kind: Secret` manifests.

Why it matters: Kubernetes Secrets are base64-encoded, not encrypted. Storing them in the repository exposes them to anyone with read access.

Recommendation: use external secret management (Sealed Secrets, External Secrets Operator, Vault).

### TRUST-K8S006: Kubernetes manifest uses hostPath volume

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `hostPath:` volume mounts in workload manifests.

Why it matters: hostPath volumes can expose host directories to containers, breaking isolation.

Recommendation: avoid hostPath volumes. Prefer PVCs or projected volumes.

### TRUST-K8S007: Kubernetes container adds broad Linux capabilities

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `capabilities.add` entries with `SYS_ADMIN`, `NET_ADMIN`, or `ALL`.

Why it matters: adding broad capabilities increases the attack surface and potential impact of a compromised container.

Recommendation: drop all capabilities and add only those strictly needed.

### TRUST-K8S008: Kubernetes container allows privilege escalation

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `allowPrivilegeEscalation: true`.

Why it matters: allowing privilege escalation lets a process gain more privileges than its parent, increasing risk.

Recommendation: set `allowPrivilegeEscalation: false` unless the container genuinely needs it.
