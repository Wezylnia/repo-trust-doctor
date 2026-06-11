using System.Text.RegularExpressions;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.PackageRegistryConfig;

public sealed partial class PackageRegistryConfigAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] ConfigFiles =
    [
        ".npmrc", ".yarnrc", ".yarnrc.yml",
        "pip.conf", "nuget.config", "NuGet.config",
        "gradle.properties", "settings.gradle", "settings.gradle.kts",
        "settings.xml"
    ];

    public string Id => "package-registry-config";
    public string DisplayName => "Package Registry Configuration";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-REG001", "Package registry uses HTTP", AnalysisCategory.Dependencies, Severity.High, Confidence.High,
            "A registry URL uses http://.", "Use https:// for all package registries."),
        new("TRUST-REG002", "npm always-auth enabled globally", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium,
            "always-auth=true is set globally in .npmrc.", "Scope auth to specific registries."),
        new("TRUST-REG003", "Inline package registry token", AnalysisCategory.Security, Severity.High, Confidence.Medium,
            "A literal token or password found in registry config.", "Use environment variables instead of inline credentials."),
        new("TRUST-REG004", "Maven mirror redirects all repositories", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium,
            "A mirrorOf=* redirects all repositories to a non-default host.", "Review Maven mirror configuration."),
        new("TRUST-REG005", "Gradle allows insecure protocol", AnalysisCategory.Dependencies, Severity.High, Confidence.High,
            "allowInsecureProtocol=true found.", "Remove allowInsecureProtocol or set to false."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var pattern in ConfigFiles)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!RepositoryFileSystem.CanReadAsText(file)) continue;
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
                var content = await File.ReadAllTextAsync(file, cancellationToken);
                var scanContent = file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
                    ? content
                    : StripLineComments(content);

                CheckHttpRegistry(scanContent, relativePath, findings);
                CheckAlwaysAuth(scanContent, relativePath, findings);
                CheckInlineToken(scanContent, relativePath, findings);
                CheckMavenMirrorAll(file, relativePath, findings);
                CheckInsecureProtocol(scanContent, relativePath, findings);
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private void CheckHttpRegistry(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match m in HttpRegistryPattern().Matches(content))
        {
            var url = m.Value.Trim();
            if (url.Contains("localhost") || url.Contains("127.0.0.1") || url.Contains("[::1]")) continue;
            findings.Add(F("TRUST-REG001", "HTTP registry URL", Severity.High, relativePath, $"Registry URL uses http://: {url}"));
        }
    }

    private void CheckAlwaysAuth(string content, string relativePath, List<Finding> findings)
    {
        if (GlobalAlwaysAuthPattern().IsMatch(content) && !ScopedAlwaysAuthPattern().IsMatch(content))
            findings.Add(F("TRUST-REG002", "Global always-auth", Severity.Medium, relativePath, "always-auth=true is not scoped to a registry.", Confidence.Medium));
    }

    private void CheckInlineToken(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match m in InlineTokenPattern().Matches(content))
        {
            var val = m.Groups["value"].Value.Trim('"', '\'');
            if (val.Contains("${") || val.Contains('%') || val.Contains("$env:") || val.StartsWith('$')) continue;
            findings.Add(F("TRUST-REG003", "Inline registry token", Severity.High, relativePath, $"Credential key '{m.Groups["key"].Value}' has a literal value.", Confidence.Medium));
        }
    }

    private void CheckMavenMirrorAll(string file, string relativePath, List<Finding> findings)
    {
        if (!file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            var doc = XDocument.Load(file);
            var mirrors = doc.Descendants().Where(e => e.Name.LocalName == "mirror");
            foreach (var mirror in mirrors)
            {
                var mirrorOf = mirror.Elements().FirstOrDefault(e => e.Name.LocalName == "mirrorOf")?.Value;
                var url = mirror.Elements().FirstOrDefault(e => e.Name.LocalName == "url")?.Value ?? "";
                if (mirrorOf == "*" && !url.Contains("localhost") && !url.Contains(".corp") && !url.Contains(".internal"))
                    findings.Add(F("TRUST-REG004", "Maven mirror-all", Severity.Medium, relativePath, $"mirrorOf=* redirects to {url}.", Confidence.Medium));
            }
        }
        catch { /* skip unparseable XML */ }
    }

    private void CheckInsecureProtocol(string content, string relativePath, List<Finding> findings)
    {
        if (InsecureProtocolPattern().IsMatch(content))
            findings.Add(F("TRUST-REG005", "Insecure protocol allowed", Severity.High, relativePath, "allowInsecureProtocol is set to true."));
    }

    private static Finding F(string rid, string title, Severity sev, string path, string ev, Confidence conf = Confidence.High)
        => new(rid, title, AnalysisCategory.Dependencies, sev, conf, title,
            [new Evidence("registry-config", ev, path)],
            new Recommendation("Review the package registry configuration."));

    private static string StripLineComments(string content)
    {
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith('#') || trimmed.StartsWith("//"))
                lines[i] = "";
        }

        return string.Join('\n', lines);
    }

    [GeneratedRegex(@"http://[^\s""'>]+")]
    private static partial Regex HttpRegistryPattern();

    [GeneratedRegex(@"(?mi)^\s*always-auth\s*=\s*true\s*$")]
    private static partial Regex GlobalAlwaysAuthPattern();

    [GeneratedRegex(@"//[^/]+\.[^/]+/:_authToken")]
    private static partial Regex ScopedAlwaysAuthPattern();

    [GeneratedRegex(@"(?mi)(?<key>_authToken|password|ClearTextPassword)\s*[=:]\s*(?<value>\S+)")]
    private static partial Regex InlineTokenPattern();

    [GeneratedRegex(@"allowInsecureProtocol\s*[=:]\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex InsecureProtocolPattern();
}
