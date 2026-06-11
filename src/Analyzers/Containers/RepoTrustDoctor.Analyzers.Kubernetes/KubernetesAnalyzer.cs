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
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.yaml")
                     .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.yml")))
        {
            var fileName = Path.GetFileName(file);
            // Only scan files that look like Kubernetes manifests
            if (!fileName.Contains("deployment", StringComparison.OrdinalIgnoreCase) &&
                !fileName.Contains("daemonset", StringComparison.OrdinalIgnoreCase) &&
                !fileName.Contains("statefulset", StringComparison.OrdinalIgnoreCase) &&
                !fileName.Contains("pod", StringComparison.OrdinalIgnoreCase) &&
                !fileName.Contains("secret", StringComparison.OrdinalIgnoreCase) &&
                !fileName.Contains("configmap", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

            CheckPrivileged(content, relativePath, findings);
            CheckHostNamespace(content, relativePath, findings);
            CheckRunAsNonRoot(content, relativePath, findings);
            CheckReadOnlyRootFs(content, relativePath, findings);
            CheckSecretManifest(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckPrivileged(string content, string relativePath, List<Finding> findings)
    {
        if (PrivilegedPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-K8S001", "Kubernetes container runs in privileged mode",
                Severity.High, relativePath, "securityContext.privileged is set to true."));
        }
    }

    private static void CheckHostNamespace(string content, string relativePath, List<Finding> findings)
    {
        if (HostNamespacePattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-K8S002", "Kubernetes pod shares host namespace",
                Severity.High, relativePath, "Pod uses hostNetwork, hostPID, or hostIPC."));
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
        if (SecretKindPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-K8S005", "Kubernetes Secret manifest in repository",
                Severity.Medium, relativePath, "A Kubernetes Secret manifest was found. Values are base64-encoded, not encrypted."));
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence)
    {
        return new Finding(ruleId, title, AnalysisCategory.Containers, severity, Confidence.High, title,
            [new Evidence("kubernetes", evidence, filePath)],
            new Recommendation("Review the Kubernetes manifest and apply the recommended security hardening."));
    }

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
}
