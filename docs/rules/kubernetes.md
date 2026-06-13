# Kubernetes Manifest Rules

Kubernetes rules focus on runtime manifests. Common example, sample, fixture, mock, generated `artifacts`, playground, test, testing, vendored, and `testdata` paths are ignored so large projects that keep Kubernetes API fixtures in source control do not receive production-risk findings for non-runtime manifests. Kubernetes API fixture paths such as managed-fields and field-manager YAML fixtures are also skipped.

## TRUST-K8S001: Kubernetes container runs in privileged mode

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `securityContext.privileged: true`.

Why it matters: privileged containers have almost full host capabilities and can escape isolation.

Recommendation: avoid privileged containers. Use specific Linux capabilities instead.

## TRUST-K8S002: Kubernetes pod shares host namespace

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `hostNetwork`, `hostPID`, or `hostIPC` set to true.

Why it matters: sharing host namespaces breaks container isolation and can expose the host to the container.

Recommendation: avoid sharing host namespaces unless absolutely necessary.

## TRUST-K8S003: Kubernetes container may run as root

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects missing `runAsNonRoot: true`.

Why it matters: containers running as root have full privileges inside the container and can escalate more easily.

Recommendation: set `securityContext.runAsNonRoot: true` and specify a non-root user.

## TRUST-K8S004: Kubernetes container has writable root filesystem

- Category: Containers
- Default severity: Low
- Default confidence: High

Detects missing `readOnlyRootFilesystem: true`.

Why it matters: a writable root filesystem allows attackers to modify binaries and configurations after compromise.

Recommendation: set `securityContext.readOnlyRootFilesystem: true` for immutable infrastructure.

## TRUST-K8S005: Kubernetes Secret manifest in repository

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `kind: Secret` manifests.

Why it matters: Kubernetes Secrets are base64-encoded, not encrypted. Storing them in the repository exposes them to anyone with read access.

Recommendation: use external secret management (Sealed Secrets, External Secrets Operator, Vault).

## TRUST-K8S006: Kubernetes manifest uses hostPath volume

- Category: Containers
- Default severity: High
- Default confidence: High

Detects `hostPath:` volume mounts in workload manifests. Multiple `hostPath` volumes in the same manifest are reported as one finding with a count, rather than one finding per volume.

Why it matters: hostPath volumes can expose host directories to containers, breaking isolation.

Recommendation: avoid hostPath volumes. Prefer PVCs or projected volumes.

## TRUST-K8S007: Kubernetes container adds broad Linux capabilities

- Category: Containers
- Default severity: High (SYS_ADMIN, ALL) / Medium (NET_ADMIN)
- Default confidence: High

Detects `capabilities.add` entries with `SYS_ADMIN`, `NET_ADMIN`, or `ALL`.

Why it matters: adding broad capabilities increases the attack surface and potential impact of a compromised container.

Recommendation: drop all capabilities and add only those strictly needed.

## TRUST-K8S008: Kubernetes container allows privilege escalation

- Category: Containers
- Default severity: Medium
- Default confidence: High

Detects `allowPrivilegeEscalation: true`.

Why it matters: allowing privilege escalation lets a process gain more privileges than its parent, increasing risk.

Recommendation: set `allowPrivilegeEscalation: false` unless the container genuinely needs it.
