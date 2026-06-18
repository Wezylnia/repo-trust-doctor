namespace RepoTrustDoctor.Analyzers.Kubernetes;

/// <summary>
/// Parsed representation of a Kubernetes YAML document containing one or more workloads.
/// </summary>
internal sealed record KubernetesWorkloadDocument(
    string RelativePath,
    IReadOnlyList<KubernetesWorkload> Workloads,
    IReadOnlyList<string> Warnings);

/// <summary>
/// A single Kubernetes workload (Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod).
/// </summary>
internal sealed record KubernetesWorkload(
    string Kind,
    string? Name,
    string? Namespace,
    IReadOnlyList<KubernetesContainer> Containers,
    KubernetesSecurityContext PodSecurityContext,
    int StartLine);

/// <summary>
/// A single container definition within a workload.
/// </summary>
internal sealed record KubernetesContainer(
    string Name,
    KubernetesSecurityContext SecurityContext,
    KubernetesResourceRequirements Resources,
    int StartLine);

/// <summary>
/// Security context values (pod-level or container-level).
/// All properties are nullable — null means "not configured".
/// </summary>
internal sealed record KubernetesSecurityContext(
    string? SeccompProfileType,
    IReadOnlyList<string> CapabilityAdds,
    IReadOnlyList<string> CapabilityDrops,
    int? StartLine);

/// <summary>
/// Resource requirements (only limits are tracked for K8S011).
/// </summary>
internal sealed record KubernetesResourceRequirements(
    bool HasCpuLimit,
    bool HasMemoryLimit,
    int? LimitsLine);
