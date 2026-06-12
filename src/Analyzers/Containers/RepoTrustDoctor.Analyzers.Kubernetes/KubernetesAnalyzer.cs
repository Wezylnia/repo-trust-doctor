using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Kubernetes;

public sealed partial class KubernetesAnalyzer : IRepositoryAnalyzer
{
    public string Id => "kubernetes-security";

    public string DisplayName => "Kubernetes Manifest Security";

    public AnalysisCategory Category => AnalysisCategory.Containers;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-K8S001", "Kubernetes container runs in privileged mode", AnalysisCategory.Containers, Severity.High, Confidence.High,
            "A container is configured with securityContext.privileged: true.", "Avoid privileged containers. Use specific Linux capabilities instead."),
        new("TRUST-K8S002", "Kubernetes pod shares host namespace", AnalysisCategory.Containers, Severity.High, Confidence.High,
            "The pod uses hostNetwork, hostPID, or hostIPC.", "Avoid sharing host namespaces unless absolutely necessary."),
        new("TRUST-K8S003", "Kubernetes container may run as root", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "runAsNonRoot is not set to true.", "Set securityContext.runAsNonRoot: true and specify a non-root user."),
        new("TRUST-K8S004", "Kubernetes container has writable root filesystem", AnalysisCategory.Containers, Severity.Low, Confidence.High,
            "readOnlyRootFilesystem is not set to true.", "Set securityContext.readOnlyRootFilesystem: true for immutable infrastructure."),
        new("TRUST-K8S005", "Kubernetes Secret manifest in repository", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A Kubernetes Secret manifest was found. Values are base64-encoded, not encrypted.", "Use external secret management (e.g., Sealed Secrets, Vault) instead of storing Secrets in the repository."),
        new("TRUST-K8S006", "Kubernetes manifest uses hostPath volume", AnalysisCategory.Containers, Severity.High, Confidence.High,
            "A workload manifest mounts a hostPath volume.", "Avoid hostPath volumes unless strictly required. Prefer PVCs or projected volumes."),
        new("TRUST-K8S007", "Kubernetes container adds broad Linux capabilities", AnalysisCategory.Containers, Severity.High, Confidence.High,
            "A container adds SYS_ADMIN, NET_ADMIN, or ALL capabilities.", "Drop all capabilities and add only those strictly needed by the application."),
        new("TRUST-K8S008", "Kubernetes container allows privilege escalation", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A container has allowPrivilegeEscalation set to true.", "Set allowPrivilegeEscalation: false unless the container genuinely needs it."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.yaml")
                     .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.yml")))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
            if (IsExampleFixturePath(relativePath))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            if (!LooksLikeKubernetesManifest(content))
            {
                continue;
            }

            if (HasPodTemplateOrContainerSpec(content))
            {
                CheckPrivileged(content, relativePath, findings);
                CheckHostNamespace(content, relativePath, findings);
                CheckRunAsNonRoot(content, relativePath, findings);
                CheckReadOnlyRootFs(content, relativePath, findings);
                CheckHostPathVolumes(content, relativePath, findings);
                CheckCapabilityAdds(content, relativePath, findings);
                CheckPrivilegeEscalation(content, relativePath, findings);
            }
            CheckSecretManifest(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckPrivileged(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in PrivilegedPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S001", "Kubernetes container runs in privileged mode",
                Severity.High, relativePath, "securityContext.privileged is set to true.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckHostNamespace(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in HostNamespacePattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S002", "Kubernetes pod shares host namespace",
                Severity.High, relativePath, "Pod uses hostNetwork, hostPID, or hostIPC.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckRunAsNonRoot(string content, string relativePath, List<Finding> findings)
    {
        if (!RunAsNonRootPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-K8S003", "Kubernetes container may run as root",
                Severity.Medium, relativePath, "runAsNonRoot is not explicitly set to true."));
        }
    }

    private static void CheckReadOnlyRootFs(string content, string relativePath, List<Finding> findings)
    {
        if (!ReadOnlyRootFsPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-K8S004", "Kubernetes container has writable root filesystem",
                Severity.Low, relativePath, "readOnlyRootFilesystem is not set to true."));
        }
    }

    private static void CheckSecretManifest(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in SecretKindPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S005", "Kubernetes Secret manifest in repository",
                Severity.Medium, relativePath, "A Kubernetes Secret manifest was found. Values are base64-encoded, not encrypted.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckHostPathVolumes(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in HostPathPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S006", "Kubernetes manifest uses hostPath volume",
                Severity.High, relativePath, "A workload mounts a hostPath volume. Prefer PVCs or projected volumes.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckCapabilityAdds(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in CapabilityAddPattern().Matches(content))
        {
            var cap = match.Groups["cap"].Value;
            var severity = cap is "SYS_ADMIN" or "ALL" ? Severity.High : Severity.Medium;
            findings.Add(CreateFinding("TRUST-K8S007", "Kubernetes container adds broad capability",
                severity, relativePath, $"Container adds capability '{cap}'. Drop all capabilities and add only those needed.",
                GetLineNumber(content, match.Index), severity == Severity.High ? Confidence.High : Confidence.Medium));
        }
    }

    private static void CheckPrivilegeEscalation(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in AllowPrivilegeEscalationPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S008", "Kubernetes container allows privilege escalation",
                Severity.Medium, relativePath, "allowPrivilegeEscalation is set to true. Set to false unless needed.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.Containers, severity, confidence, title,
            [new Evidence("kubernetes", evidence, filePath, lineNumber)],
            new Recommendation("Review the Kubernetes manifest and apply the recommended security hardening."));
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    private static bool LooksLikeKubernetesManifest(string content) =>
        ApiVersionPattern().IsMatch(content) &&
        KubernetesKindPattern().IsMatch(content);

    private static bool HasPodTemplateOrContainerSpec(string content) =>
        ContainerSpecPattern().IsMatch(content) &&
        WorkloadKindPattern().IsMatch(content);

    private static bool IsExampleFixturePath(string relativePath) =>
        relativePath.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("test/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("testing/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/testing/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("integration-test", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("smoke-test", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("dockertest", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("testfixtures", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("testassets", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/testdata/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("testdata/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("fixtures/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("examples/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/examples/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("samples/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/samples/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.StartsWith("playground/", StringComparison.OrdinalIgnoreCase) ||
        relativePath.Contains("/playground/", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"privileged\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex PrivilegedPattern();

    [GeneratedRegex(@"(hostNetwork|hostPID|hostIPC)\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex HostNamespacePattern();

    [GeneratedRegex(@"runAsNonRoot\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex RunAsNonRootPattern();

    [GeneratedRegex(@"readOnlyRootFilesystem\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex ReadOnlyRootFsPattern();

    [GeneratedRegex(@"kind\s*:\s*Secret", RegexOptions.IgnoreCase)]
    private static partial Regex SecretKindPattern();

    [GeneratedRegex(@"(?mi)^\s*apiVersion\s*:\s*\S+")]
    private static partial Regex ApiVersionPattern();

    [GeneratedRegex(@"(?mi)^\s*kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob|ReplicaSet|ReplicationController|Secret)\s*$")]
    private static partial Regex KubernetesKindPattern();

    [GeneratedRegex(@"(?mi)^\s*kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob|ReplicaSet|ReplicationController)\s*$")]
    private static partial Regex WorkloadKindPattern();

    [GeneratedRegex(@"(?mi)^\s*(containers|initContainers)\s*:\s*$")]
    private static partial Regex ContainerSpecPattern();
    [GeneratedRegex(@"(?m)^\s*hostPath\s*:\s*$")]
    private static partial Regex HostPathPattern();

    [GeneratedRegex(@"(?m)add\s*:\s*\[.*?""(?<cap>SYS_ADMIN|NET_ADMIN|ALL)""")]
    private static partial Regex CapabilityAddPattern();

    [GeneratedRegex(@"allowPrivilegeEscalation\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex AllowPrivilegeEscalationPattern();}
