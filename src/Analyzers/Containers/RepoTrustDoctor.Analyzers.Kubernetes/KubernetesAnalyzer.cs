using System.Text.RegularExpressions;
using System.Text;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Kubernetes;

public sealed partial class KubernetesAnalyzer : IRepositoryAnalyzer
{
    private const int ManifestProbeBytes = 16 * 1024;

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
        new("TRUST-K8S009", "Kubernetes automounts service account token", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A pod explicitly enables automountServiceAccountToken.", "Disable service account token automounting unless the workload needs Kubernetes API access."),
        new("TRUST-K8S012", "Kubernetes container image uses mutable tag", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A container image is not pinned by digest or uses latest/no tag.", "Pin container images to immutable digests or explicit, reviewed version tags."),
        new("TRUST-K8S013", "Kubernetes container uses hostPort", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A container binds a port directly on the node.", "Avoid hostPort unless node-level exposure is required. Prefer Services or Ingress."),
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

            var probe = await ReadManifestProbeAsync(file, cancellationToken);
            if (!LooksLikeKubernetesManifest(probe))
            {
                continue;
            }

            var content = new FileInfo(file).Length <= ManifestProbeBytes
                ? probe
                : await File.ReadAllTextAsync(file, cancellationToken);

            if (HasPodTemplateOrContainerSpec(content))
            {
                var containers = ExtractContainerStates(content);
                CheckPrivileged(containers, relativePath, findings);
                CheckHostNamespace(content, relativePath, findings);
                CheckRunAsNonRoot(containers, relativePath, findings);
                CheckReadOnlyRootFs(containers, relativePath, findings);
                CheckHostPathVolumes(content, relativePath, findings);
                CheckCapabilityAdds(containers, relativePath, findings);
                CheckPrivilegeEscalation(containers, relativePath, findings);
                CheckServiceAccountTokenAutomount(content, relativePath, findings);
                CheckMutableImages(content, relativePath, findings);
                CheckHostPorts(content, relativePath, findings);
            }
            CheckSecretManifest(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckPrivileged(IReadOnlyCollection<ContainerSecurityState> containers, string relativePath, List<Finding> findings)
    {
        foreach (var container in containers.Where(static container => container.IsPrivileged))
        {
            findings.Add(CreateFinding("TRUST-K8S001", "Kubernetes container runs in privileged mode",
                Severity.High, relativePath, $"{container.DisplayName} sets securityContext.privileged: true.",
                container.LineNumber));
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

    private static void CheckRunAsNonRoot(IReadOnlyCollection<ContainerSecurityState> containers, string relativePath, List<Finding> findings)
    {
        foreach (var container in containers.Where(static container => !container.RunAsNonRoot))
        {
            findings.Add(CreateFinding("TRUST-K8S003", "Kubernetes container may run as root",
                Severity.Medium, relativePath, $"{container.DisplayName} does not explicitly set runAsNonRoot: true.",
                container.LineNumber));
        }
    }

    private static void CheckReadOnlyRootFs(IReadOnlyCollection<ContainerSecurityState> containers, string relativePath, List<Finding> findings)
    {
        foreach (var container in containers.Where(static container => !container.ReadOnlyRootFilesystem))
        {
            findings.Add(CreateFinding("TRUST-K8S004", "Kubernetes container has writable root filesystem",
                Severity.Low, relativePath, $"{container.DisplayName} does not set readOnlyRootFilesystem: true.",
                container.LineNumber));
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
        var matches = HostPathPattern().Matches(content);
        if (matches.Count == 0)
        {
            return;
        }

        var message = matches.Count == 1
            ? "A workload mounts a hostPath volume. Prefer PVCs or projected volumes."
            : $"A workload mounts {matches.Count} hostPath volumes. Prefer PVCs or projected volumes.";
        findings.Add(CreateFinding("TRUST-K8S006", "Kubernetes manifest uses hostPath volume",
            Severity.High, relativePath, message,
            GetLineNumber(content, matches[0].Index)));
    }

    private static void CheckCapabilityAdds(IReadOnlyCollection<ContainerSecurityState> containers, string relativePath, List<Finding> findings)
    {
        foreach (var container in containers.Where(static container => container.AddedCapabilities.Count > 0))
        {
            var cap = container.AddedCapabilities[0];
            var severity = cap is "SYS_ADMIN" or "ALL" ? Severity.High : Severity.Medium;
            findings.Add(CreateFinding("TRUST-K8S007", "Kubernetes container adds broad capability",
                severity, relativePath, $"{container.DisplayName} adds capability '{cap}'. Drop all capabilities and add only those needed.",
                container.LineNumber, severity == Severity.High ? Confidence.High : Confidence.Medium));
        }
    }

    private static void CheckPrivilegeEscalation(IReadOnlyCollection<ContainerSecurityState> containers, string relativePath, List<Finding> findings)
    {
        foreach (var container in containers.Where(static container => container.AllowPrivilegeEscalation))
        {
            findings.Add(CreateFinding("TRUST-K8S008", "Kubernetes container allows privilege escalation",
                Severity.Medium, relativePath, $"{container.DisplayName} sets allowPrivilegeEscalation: true. Set to false unless needed.",
                container.LineNumber));
        }
    }

    private static void CheckServiceAccountTokenAutomount(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in AutomountServiceAccountTokenPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S009", "Kubernetes automounts service account token",
                Severity.Medium, relativePath, "Pod explicitly sets automountServiceAccountToken: true.",
                GetLineNumber(content, match.Index)));
            break;
        }
    }

    private static void CheckMutableImages(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in ImagePattern().Matches(content))
        {
            var image = match.Groups["image"].Value.Trim().Trim('"', '\'');
            if (!IsMutableContainerImage(image))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-K8S012", "Kubernetes container image uses mutable tag",
                Severity.Medium, relativePath, $"Container image `{image}` is not pinned by digest or uses latest/no tag.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckHostPorts(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in HostPortPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-K8S013", "Kubernetes container uses hostPort",
                Severity.Medium, relativePath, $"Container binds hostPort {match.Groups["port"].Value} directly on the node.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static bool IsMutableContainerImage(string image)
    {
        if (string.IsNullOrWhiteSpace(image) ||
            image.Contains("@sha256:", StringComparison.OrdinalIgnoreCase) ||
            image.Contains('$', StringComparison.Ordinal) ||
            image.Contains("{{", StringComparison.Ordinal))
        {
            return false;
        }

        var lastSlash = image.LastIndexOf('/');
        var lastColon = image.LastIndexOf(':');
        if (lastColon <= lastSlash)
        {
            return true;
        }

        return image[(lastColon + 1)..].Equals("latest", StringComparison.OrdinalIgnoreCase);
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

    private static async Task<string> ReadManifestProbeAsync(string file, CancellationToken cancellationToken)
    {
        var buffer = new byte[ManifestProbeBytes];
        await using var stream = File.OpenRead(file);
        var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static bool HasPodTemplateOrContainerSpec(string content) =>
        ContainerSpecPattern().IsMatch(content) &&
        WorkloadKindPattern().IsMatch(content);

    private static IReadOnlyList<ContainerSecurityState> ExtractContainerStates(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        var states = new List<ContainerSecurityState>();

        foreach (var document in ExtractDocumentRanges(lines))
        {
            var ranges = ExtractContainerRanges(lines, document);
            var podRunAsNonRoot = HasPodRunAsNonRoot(lines, ranges, document);
            states.AddRange(ranges.Select(range =>
            {
                var containerLines = lines.Skip(range.Start).Take(range.EndExclusive - range.Start).ToArray();
                var text = string.Join('\n', containerLines);
                return new ContainerSecurityState(
                    ExtractContainerName(containerLines),
                    range.Start + 1,
                    podRunAsNonRoot || RunAsNonRootPattern().IsMatch(text),
                    ReadOnlyRootFsPattern().IsMatch(text),
                    PrivilegedPattern().IsMatch(text),
                    AllowPrivilegeEscalationPattern().IsMatch(text),
                    ReadAddedCapabilities(text));
            }));
        }

        return states;
    }

    private static IReadOnlyList<LineRange> ExtractDocumentRanges(string[] lines)
    {
        var ranges = new List<LineRange>();
        var start = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            if (!DocumentSeparatorPattern().IsMatch(lines[i]))
            {
                continue;
            }

            ranges.Add(new LineRange(start, i));
            start = i + 1;
        }

        ranges.Add(new LineRange(start, lines.Length));
        return ranges;
    }

    private static IReadOnlyList<LineRange> ExtractContainerRanges(string[] lines, LineRange document)
    {
        var ranges = new List<LineRange>();

        for (var i = document.Start; i < document.EndExclusive; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed is not ("containers:" or "initContainers:" or "ephemeralContainers:"))
            {
                continue;
            }

            var blockIndent = CountIndent(lines[i]);
            var blockEnd = FindContainerBlockEnd(lines, i + 1, blockIndent, document.EndExclusive);
            var itemIndent = FindFirstListItemIndent(lines, i + 1, blockEnd, blockIndent);
            if (itemIndent is null)
            {
                continue;
            }

            for (var cursor = i + 1; cursor < blockEnd; cursor++)
            {
                if (!IsListItem(lines[cursor], itemIndent.Value))
                {
                    continue;
                }

                var itemEnd = FindContainerItemEnd(lines, cursor + 1, blockEnd, itemIndent.Value);
                ranges.Add(new LineRange(cursor, itemEnd));
                cursor = itemEnd - 1;
            }
        }

        return ranges;
    }

    private static int? FindFirstListItemIndent(string[] lines, int start, int blockEnd, int blockIndent)
    {
        for (var i = start; i < blockEnd; i++)
        {
            if (CountIndent(lines[i]) >= blockIndent && lines[i].TrimStart().StartsWith("- ", StringComparison.Ordinal))
            {
                return CountIndent(lines[i]);
            }
        }

        return null;
    }

    private static int FindContainerBlockEnd(string[] lines, int start, int blockIndent, int documentEnd)
    {
        for (var i = start; i < documentEnd; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i]))
            {
                continue;
            }

            var indent = CountIndent(lines[i]);
            if (indent <= blockIndent && !lines[i].TrimStart().StartsWith("- ", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return documentEnd;
    }

    private static int FindContainerItemEnd(string[] lines, int start, int blockEnd, int itemIndent)
    {
        for (var i = start; i < blockEnd; i++)
        {
            if (IsListItem(lines[i], itemIndent))
            {
                return i;
            }
        }

        return blockEnd;
    }

    private static bool HasPodRunAsNonRoot(string[] lines, IReadOnlyList<LineRange> containerRanges, LineRange document)
    {
        for (var i = document.Start; i < document.EndExclusive; i++)
        {
            if (!RunAsNonRootPattern().IsMatch(lines[i]) || containerRanges.Any(range => range.Contains(i)))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    private static string ExtractContainerName(string[] containerLines)
    {
        foreach (var line in containerLines)
        {
            var match = ContainerNamePattern().Match(line);
            if (match.Success)
            {
                return $"Container '{match.Groups["name"].Value.Trim('"', '\'')}'";
            }
        }

        return "Container";
    }

    private static bool IsListItem(string line, int indent) =>
        CountIndent(line) == indent && line.TrimStart().StartsWith("- ", StringComparison.Ordinal);

    private static int CountIndent(string line)
    {
        var count = 0;
        while (count < line.Length && line[count] == ' ')
        {
            count++;
        }

        return count;
    }

    private static bool IsExampleFixturePath(string relativePath) =>
        RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath) ||
        IsKubernetesApiFixturePath(relativePath);

    private static bool IsKubernetesApiFixturePath(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');
        return normalized.Contains("/pkg/util/managedfields/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/pkg/endpoints/handlers/fieldmanager/", StringComparison.OrdinalIgnoreCase);
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

    [GeneratedRegex(@"(?mi)^\s*apiVersion\s*:\s*\S+")]
    private static partial Regex ApiVersionPattern();

    [GeneratedRegex(@"(?mi)^\s*kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob|ReplicaSet|ReplicationController|Secret)\s*$")]
    private static partial Regex KubernetesKindPattern();

    [GeneratedRegex(@"(?mi)^\s*kind\s*:\s*(Deployment|DaemonSet|StatefulSet|Pod|Job|CronJob|ReplicaSet|ReplicationController)\s*$")]
    private static partial Regex WorkloadKindPattern();

    [GeneratedRegex(@"(?mi)^\s*(containers|initContainers|ephemeralContainers)\s*:\s*$")]
    private static partial Regex ContainerSpecPattern();

    [GeneratedRegex(@"(?m)^\s*hostPath\s*:\s*$")]
    private static partial Regex HostPathPattern();

    [GeneratedRegex(@"allowPrivilegeEscalation\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex AllowPrivilegeEscalationPattern();

    [GeneratedRegex(@"(?mi)^\s*automountServiceAccountToken\s*:\s*true\s*(?:#.*)?$")]
    private static partial Regex AutomountServiceAccountTokenPattern();

    [GeneratedRegex(@"(?mi)^\s*image\s*:\s*(?<image>[""']?[^""'\s#]+[""']?)")]
    private static partial Regex ImagePattern();

    [GeneratedRegex(@"(?mi)^\s*hostPort\s*:\s*(?<port>\d+)\s*(?:#.*)?$")]
    private static partial Regex HostPortPattern();

    [GeneratedRegex(@"""(?<cap>SYS_ADMIN|NET_ADMIN|ALL)""", RegexOptions.IgnoreCase)]
    private static partial Regex CapabilityNamePattern();

    [GeneratedRegex(@"^\s*(?:-\s*)?name\s*:\s*(?<name>[^#\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex ContainerNamePattern();

    [GeneratedRegex(@"^\s*---\s*(?:#.*)?$")]
    private static partial Regex DocumentSeparatorPattern();

    private sealed record LineRange(int Start, int EndExclusive)
    {
        public bool Contains(int lineIndex) => lineIndex >= Start && lineIndex < EndExclusive;
    }

    private sealed record ContainerSecurityState(
        string DisplayName,
        int LineNumber,
        bool RunAsNonRoot,
        bool ReadOnlyRootFilesystem,
        bool IsPrivileged,
        bool AllowPrivilegeEscalation,
        IReadOnlyList<string> AddedCapabilities);

    private static string[] ReadAddedCapabilities(string text)
    {
        if (!text.Contains("capabilities", StringComparison.OrdinalIgnoreCase) ||
            !text.Contains("add", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        return CapabilityNamePattern()
            .Matches(text)
            .Select(match => match.Groups["cap"].Value.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
