using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Kubernetes;

/// <summary>
/// Security context checks for Kubernetes workloads.
/// Produces TRUST-K8S010, TRUST-K8S011, and TRUST-K8S014 findings.
/// Every repeatable finding includes a stable identity key.
/// </summary>
internal static class KubernetesSecurityContextChecks
{
    public static void CheckAll(KubernetesWorkloadDocument document, List<Finding> findings)
    {
        foreach (var workload in document.Workloads)
        {
            foreach (var container in workload.Containers)
            {
                CheckSeccompProfile(document.RelativePath, workload, container, findings);
                CheckResourceLimits(document.RelativePath, workload, container, findings);
                CheckCapabilityDrop(document.RelativePath, workload, container, findings);
            }
        }
    }

    // ── TRUST-K8S010: Seccomp profile ────────────────────────────────

    private static void CheckSeccompProfile(
        string relativePath,
        KubernetesWorkload workload,
        KubernetesContainer container,
        List<Finding> findings)
    {
        // Effective seccomp: container-level overrides pod-level.
        var effectiveSeccomp = container.SecurityContext.SeccompProfileType
                               ?? workload.PodSecurityContext.SeccompProfileType;

        if (effectiveSeccomp is "RuntimeDefault" or "Localhost")
        {
            return; // PASS
        }

        var workloadName = workload.Name ?? "<unnamed>";
        var identityKey = $"k8s010|{relativePath}|{workload.Kind}|{workloadName}|{container.Name}";

        var (title, message, confidence) = effectiveSeccomp switch
        {
            "Unconfined" => (
                "Seccomp is explicitly configured as Unconfined",
                $"Seccomp is explicitly configured as Unconfined for container '{container.Name}' in {workload.Kind} '{workloadName}'.",
                Confidence.High),
            null => (
                "Seccomp profile is not explicitly configured",
                $"No explicit seccomp profile was found for container '{container.Name}' in {workload.Kind} '{workloadName}'. The cluster may apply a default profile, but that cannot be verified statically.",
                Confidence.Medium),
            _ => (
                "Seccomp profile is not recognized",
                $"Seccomp profile '{effectiveSeccomp}' for container '{container.Name}' in {workload.Kind} '{workloadName}' is not recognized as RuntimeDefault or Localhost.",
                Confidence.Medium)
        };

        findings.Add(new Finding(
            "TRUST-K8S010",
            title,
            AnalysisCategory.Containers,
            Severity.Low,
            confidence,
            message,
            [new Evidence("kubernetes-security-context", message, relativePath, container.StartLine)],
            new Recommendation("Set seccompProfile.type: RuntimeDefault or Localhost in the pod or container securityContext."),
            IdentityKey: identityKey));
    }

    // ── TRUST-K8S011: Resource limits ────────────────────────────────

    private static void CheckResourceLimits(
        string relativePath,
        KubernetesWorkload workload,
        KubernetesContainer container,
        List<Finding> findings)
    {
        var resources = container.Resources;

        // PASS: both CPU and memory limits are present.
        if (resources.HasCpuLimit && resources.HasMemoryLimit)
        {
            return;
        }

        // No limits block at all — report both missing.
        string message;
        if (!resources.HasCpuLimit && !resources.HasMemoryLimit)
        {
            message = $"Container '{container.Name}' does not declare CPU or memory limits.";
        }
        else if (!resources.HasCpuLimit)
        {
            message = $"Container '{container.Name}' declares memory limits but not CPU limits.";
        }
        else
        {
            message = $"Container '{container.Name}' declares CPU limits but not memory limits.";
        }

        var workloadName = workload.Name ?? "<unnamed>";
        var identityKey = $"k8s011|{relativePath}|{workload.Kind}|{workloadName}|{container.Name}";
        var lineNumber = resources.LimitsLine ?? container.StartLine;

        findings.Add(new Finding(
            "TRUST-K8S011",
            "Container does not declare resource limits",
            AnalysisCategory.Containers,
            Severity.Low,
            Confidence.High,
            message,
            [new Evidence("kubernetes-resource-limits", message, relativePath, lineNumber)],
            new Recommendation("Set resources.limits.cpu and resources.limits.memory for every container."),
            IdentityKey: identityKey));
    }

    // ── TRUST-K8S014: Capabilities without drop ALL ──────────────────

    private static void CheckCapabilityDrop(
        string relativePath,
        KubernetesWorkload workload,
        KubernetesContainer container,
        List<Finding> findings)
    {
        var capabilityAdds = container.SecurityContext.CapabilityAdds;
        var capabilityDrops = container.SecurityContext.CapabilityDrops;

        // Only trigger when capabilities.add is explicitly set.
        if (capabilityAdds.Count == 0)
        {
            return;
        }

        // PASS: drop: ALL is present (case-insensitive, normalized to uppercase).
        if (capabilityDrops.Contains("ALL", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        var workloadName = workload.Name ?? "<unnamed>";
        var identityKey = $"k8s014|{relativePath}|{workload.Kind}|{workloadName}|{container.Name}";

        var capsList = string.Join(", ", capabilityAdds);
        var message = $"Container '{container.Name}' adds capabilities [{capsList}] without dropping ALL.";
        var lineNumber = container.SecurityContext.StartLine ?? container.StartLine;

        findings.Add(new Finding(
            "TRUST-K8S014",
            "Container adds capabilities without dropping ALL",
            AnalysisCategory.Containers,
            Severity.Medium,
            Confidence.High,
            message,
            [new Evidence("kubernetes-capabilities", message, relativePath, lineNumber)],
            new Recommendation("Add drop: [ALL] to the securityContext.capabilities block and only add explicitly needed capabilities."),
            IdentityKey: identityKey));
    }
}
