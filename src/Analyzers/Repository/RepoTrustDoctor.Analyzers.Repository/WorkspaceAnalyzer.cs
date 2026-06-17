using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using System.Text.Json;

namespace RepoTrustDoctor.Analyzers.Repository;

public sealed class WorkspaceAnalyzer : IRepositoryAnalyzer
{
    public string Id => "workspace-detection";

    public string DisplayName => "Workspace Detection";

    public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public IReadOnlyCollection<string> ProducesArtifacts => [WorkspaceArtifact.ArtifactKey];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(5);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-WS001", "Repository uses npm or Yarn workspaces", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses package.json workspace configuration.", "Workspaces are a valid monorepo pattern. Ensure workspace boundaries are documented."),
        new("TRUST-WS002", "Repository uses Cargo workspace", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses Cargo workspace configuration.", "Workspaces are a valid monorepo pattern. Ensure workspace members are documented."),
        new("TRUST-WS003", "Repository uses Go workspace", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High,
            "The repository uses Go workspace configuration (go.work).", "Go workspaces are a valid multi-module pattern."),
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var workspaceMembers = new List<WorkspaceMember>();
        var packageJsonFiles = RepositoryFileSystem
            .EnumerateFiles(context.RepositoryPath, "package.json")
            .ToArray();
        var cargoManifestFiles = RepositoryFileSystem
            .EnumerateFiles(context.RepositoryPath, "Cargo.toml")
            .ToArray();
        var goModuleFiles = RepositoryFileSystem
            .EnumerateFiles(context.RepositoryPath, "go.mod")
            .ToArray();

        foreach (var packageJson in packageJsonFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, packageJson);
            if (!TryReadFile(packageJson, out var content))
            {
                continue;
            }

            try
            {
                using var doc = JsonDocument.Parse(content);
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("workspaces", out var workspaces))
                {
                    var declarations = WorkspaceDeclarationParser.ReadNpmPatterns(workspaces);
                    if (declarations.Count > 0)
                    {
                        var members = WorkspaceMemberResolver.Resolve(
                            context.RepositoryPath,
                            packageJson,
                            declarations,
                            packageJsonFiles);
                        AddMembers(workspaceMembers, "npm", relativePath, members);
                        findings.Add(CreateInfoFinding(
                            "TRUST-WS001",
                            "Repository uses npm or Yarn workspaces",
                            relativePath,
                            BuildEvidence("package.json defines npm or Yarn workspaces", members.Count)));
                    }
                }
            }
            catch (JsonException)
            {
                // Skip malformed JSON
            }
        }

        foreach (var cargoToml in cargoManifestFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, cargoToml);
            if (!TryReadFile(cargoToml, out var content))
            {
                continue;
            }

            var declarations = WorkspaceDeclarationParser.ReadCargoPatterns(content);
            if (declarations.IsWorkspace)
            {
                var members = WorkspaceMemberResolver.Resolve(
                    context.RepositoryPath,
                    cargoToml,
                    declarations.Members,
                    cargoManifestFiles,
                    declarations.Excludes);
                AddMembers(workspaceMembers, "cargo", relativePath, members);
                findings.Add(CreateInfoFinding(
                    "TRUST-WS002",
                    "Repository uses Cargo workspace",
                    relativePath,
                    BuildEvidence("Cargo.toml contains a [workspace] section", members.Count)));
            }
        }

        foreach (var goWork in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "go.work"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = GetRelative(context, goWork);
            IReadOnlyList<string> members = [];
            if (TryReadFile(goWork, out var content))
            {
                var declarations = WorkspaceDeclarationParser.ReadGoUsePaths(content);
                members = WorkspaceMemberResolver.Resolve(
                    context.RepositoryPath,
                    goWork,
                    declarations,
                    goModuleFiles);
                AddMembers(workspaceMembers, "go", relativePath, members);
            }

            findings.Add(CreateInfoFinding(
                "TRUST-WS003",
                "Repository uses Go workspace",
                relativePath,
                BuildEvidence("A go.work file was found", members.Count)));
        }

        var artifacts = new List<AnalyzerArtifact>();
        if (workspaceMembers.Count > 0)
        {
            artifacts.Add(new AnalyzerArtifact(
                WorkspaceArtifact.ArtifactKey,
                new WorkspaceArtifact(workspaceMembers
                    .Distinct()
                    .OrderBy(member => member.Ecosystem, StringComparer.Ordinal)
                    .ThenBy(member => member.RootDirectory, StringComparer.Ordinal)
                    .ThenBy(member => member.MemberPath, StringComparer.Ordinal)
                    .ToArray())));
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

    private static void AddMembers(
        ICollection<WorkspaceMember> workspaceMembers,
        string ecosystem,
        string workspaceFile,
        IEnumerable<string> members)
    {
        var rootDirectory = Path.GetDirectoryName(workspaceFile)?.Replace('\\', '/') ?? "";
        foreach (var member in members)
        {
            workspaceMembers.Add(new WorkspaceMember(ecosystem, member, rootDirectory));
        }
    }

    private static string BuildEvidence(string prefix, int memberCount) =>
        memberCount == 0
            ? $"{prefix}; no existing member manifests matched its declarations."
            : $"{prefix}; {memberCount} existing member manifest(s) matched.";

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
