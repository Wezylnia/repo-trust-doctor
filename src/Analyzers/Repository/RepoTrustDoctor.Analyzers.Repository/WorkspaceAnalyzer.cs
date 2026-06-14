using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Repository;

public sealed class WorkspaceAnalyzer : IRepositoryAnalyzer
{
    public string Id => "workspace-detection";

    public string DisplayName => "Workspace Detection";

    public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(5);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-WS001", "Repository uses npm workspaces", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses npm workspace configuration.", "Workspaces are a valid monorepo pattern. Ensure workspace boundaries are documented."),
        new("TRUST-WS002", "Repository uses Cargo workspace", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses Cargo workspace configuration.", "Workspaces are a valid monorepo pattern. Ensure workspace members are documented."),
        new("TRUST-WS003", "Repository uses Go workspace", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses Go workspace configuration (go.work).", "Go workspaces are a valid multi-module pattern."),
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var workspaceMembers = new List<WorkspaceMember>();

        // npm workspaces
        foreach (var packageJson in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, packageJson);
            if (!TryReadFile(packageJson, out var content))
            {
                continue;
            }

            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(content);
                if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("workspaces", out var workspaces) &&
                    workspaces.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    findings.Add(CreateInfoFinding("TRUST-WS001", "Repository uses npm workspaces", relativePath,
                        "The root package.json defines npm workspaces."));

                    foreach (var ws in workspaces.EnumerateArray())
                    {
                        var pattern = ws.GetString();
                        if (!string.IsNullOrWhiteSpace(pattern))
                        {
                            workspaceMembers.Add(new WorkspaceMember(
                                "npm", pattern, Path.GetDirectoryName(relativePath)?.Replace('\\', '/') ?? ""));
                        }
                    }
                }
            }
            catch (System.Text.Json.JsonException)
            {
                // Skip malformed JSON
            }
        }

        // Cargo workspace
        foreach (var cargoToml in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Cargo.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, cargoToml);
            if (!TryReadFile(cargoToml, out var content))
            {
                continue;
            }

            if (content.Contains("[workspace]", StringComparison.Ordinal))
            {
                findings.Add(CreateInfoFinding("TRUST-WS002", "Repository uses Cargo workspace", relativePath,
                    "The Cargo.toml contains a [workspace] section."));

                var memberPattern = System.Text.RegularExpressions.Regex.Match(content, @"members\s*=\s*\[([^\]]+)\]");
                if (memberPattern.Success)
                {
                    foreach (var member in memberPattern.Groups[1].Value.Split(','))
                    {
                        var trimmed = member.Trim().Trim('"', '\'');
                        if (!string.IsNullOrWhiteSpace(trimmed))
                        {
                            workspaceMembers.Add(new WorkspaceMember(
                                "cargo", trimmed, Path.GetDirectoryName(relativePath)?.Replace('\\', '/') ?? ""));
                        }
                    }
                }
            }
        }

        // Go workspace
        foreach (var goWork in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "go.work"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, goWork);

            findings.Add(CreateInfoFinding("TRUST-WS003", "Repository uses Go workspace", relativePath,
                "A go.work file was found."));

            if (TryReadFile(goWork, out var content))
            {
                foreach (var line in content.Replace("\r\n", "\n").Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("./", StringComparison.Ordinal) || trimmed.EndsWith("/...", StringComparison.Ordinal))
                    {
                        workspaceMembers.Add(new WorkspaceMember(
                            "go", trimmed, Path.GetDirectoryName(relativePath)?.Replace('\\', '/') ?? ""));
                    }
                }
            }
        }

        var artifacts = new List<AnalyzerArtifact>();
        if (workspaceMembers.Count > 0)
        {
            artifacts.Add(new AnalyzerArtifact(
                WorkspaceArtifact.ArtifactKey,
                new WorkspaceArtifact(workspaceMembers)));
        }

        return Task.FromResult(AnalyzerResult.Completed(findings, artifacts, null, null));
    }

    private static Finding CreateInfoFinding(string ruleId, string title, string filePath, string evidence)
    {
        return new Finding(
            ruleId, title, AnalysisCategory.RepositoryHealth,
            Severity.Info, Confidence.High, title,
            [new Evidence("workspace", evidence, filePath)],
            new Recommendation("Workspaces are a valid monorepo pattern. Ensure workspace boundaries are documented."));
    }

    private static string GetRelative(AnalysisContext context, string filePath) =>
        Path.GetRelativePath(context.RepositoryPath, filePath).Replace('\\', '/');

    private static bool TryReadFile(string filePath, out string content)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(filePath))
        {
            return false;
        }
        try
        {
            content = File.ReadAllText(filePath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

public sealed record WorkspaceMember(string Ecosystem, string MemberPath, string RootDirectory);

public sealed record WorkspaceArtifact(IReadOnlyList<WorkspaceMember> Members)
{
    public const string ArtifactKey = "workspace";
}
