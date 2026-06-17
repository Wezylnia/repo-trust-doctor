using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Repository;

public sealed partial class RepositoryHealthAnalyzer : IRepositoryAnalyzer
{
    public string Id => "repository-health";

    public string DisplayName => "Repository Health";

    public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-REPO001", "README is missing", AnalysisCategory.RepositoryHealth, Severity.Medium, Confidence.High, "The repository does not contain a README file.", "Add a README that explains the project purpose, installation, and basic usage."),
        new("TRUST-REPO002", "LICENSE is missing", AnalysisCategory.RepositoryHealth, Severity.High, Confidence.High, "The repository does not contain a LICENSE file.", "Add a license file so users can understand whether and how the project can be used."),
        new("TRUST-REPO003", "SECURITY.md is missing", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.High, "The repository does not contain a SECURITY.md file.", "Add SECURITY.md to explain how vulnerabilities should be reported."),
        new("TRUST-REPO004", "CONTRIBUTING.md is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CONTRIBUTING.md file.", "Add contribution guidance for maintainers and contributors."),
        new("TRUST-REPO005", "CODE_OF_CONDUCT.md is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CODE_OF_CONDUCT.md file.", "Add a code of conduct if the project accepts community contribution."),
        new("TRUST-REPO006", "CODEOWNERS is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CODEOWNERS file.", "Add CODEOWNERS when ownership review should be explicit."),
        new("TRUST-REPO007", "Issue template is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain an issue template.", "Add issue templates to collect enough information from users."),
        new("TRUST-REPO008", "Pull request template is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a pull request template.", "Add a pull request template to make review expectations clear."),
        new("TRUST-REPO009", "CHANGELOG is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CHANGELOG file.", "Add a changelog to document user-facing changes in each release."),
        new("TRUST-REPO010", "README lacks installation guidance", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "The README file does not appear to contain installation instructions.", "Add installation instructions or a getting started section to the README."),
        new("TRUST-REPO011", "README lacks usage guidance", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "The README file does not appear to contain usage instructions or examples.", "Add usage instructions or examples to the README."),
        new("TRUST-REPO012", "README lacks quick start guidance", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "The README file does not appear to contain a quick start or getting started section.", "Add a short quick start section that helps users try the project quickly."),
        new("TRUST-REPO013", "Documentation folder is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a docs folder.", "Add a docs folder for architecture, usage, configuration, or operations documentation as the project grows."),
        new("TRUST-REPO014", "README contains broken-looking local link", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "The README contains a local Markdown link whose target was not found.", "Fix or remove broken README links so users can follow documentation reliably."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        CheckRequiredFile(context.RepositoryPath, ["README.md", "README.rst", "README.adoc", "README.txt", "README"], "TRUST-REPO001", "README is missing", "Add a README that explains the project purpose, installation, and basic usage.", findings, Severity.Medium);
        CheckRequiredFile(context.RepositoryPath, ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE.rst", "LICENCE", "LICENCE.md", "LICENCE.txt", "LICENCE.rst", "COPYING", "COPYING.md", "COPYING.txt", "COPYING.rst", "COPYRIGHT", "COPYRIGHT.md", "COPYRIGHT.txt"], "TRUST-REPO002", "LICENSE is missing", "Add a license file so users can understand whether and how the project can be used.", findings, Severity.High);
        CheckRequiredFile(context.RepositoryPath, ["SECURITY.md", ".github/SECURITY.md"], "TRUST-REPO003", "SECURITY.md is missing", "Add SECURITY.md to explain how vulnerabilities should be reported.", findings, Severity.Low);
        CheckRequiredFile(context.RepositoryPath, ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"], "TRUST-REPO004", "CONTRIBUTING.md is missing", "Add contribution guidance for maintainers and contributors.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, ["CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md"], "TRUST-REPO005", "CODE_OF_CONDUCT.md is missing", "Add a code of conduct if the project accepts community contribution.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/CODEOWNERS", "CODEOWNERS"], "TRUST-REPO006", "CODEOWNERS is missing", "Add CODEOWNERS when ownership review should be explicit.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/ISSUE_TEMPLATE", ".github/ISSUE_TEMPLATE.md"], "TRUST-REPO007", "Issue template is missing", "Add issue templates to collect enough information from users.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/PULL_REQUEST_TEMPLATE.md", "PULL_REQUEST_TEMPLATE.md"], "TRUST-REPO008", "Pull request template is missing", "Add a pull request template to make review expectations clear.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, ["CHANGELOG.md", "CHANGELOG.rst", "CHANGES.md", "CHANGES.rst", "CHANGELOG", "HISTORY.md", "HISTORY.rst", "RELEASES.md"], "TRUST-REPO009", "CHANGELOG is missing", "Add a changelog to document user-facing changes in each release.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, ["docs", "doc", "documentation", "guides"], "TRUST-REPO013", "Documentation folder is missing", "Add a docs folder for architecture, usage, configuration, or operations documentation as the project grows.", findings, Severity.Info);

        var readmePath = MatchReadme(context.RepositoryPath);
        if (readmePath != null && RepositoryFileSystem.CanReadAsText(readmePath))
        {
            var content = await File.ReadAllTextAsync(readmePath, cancellationToken);
            CheckReadmeSections(content, readmePath, context.RepositoryPath, findings);
            CheckReadmeLocalLinks(content, readmePath, context.RepositoryPath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static string? MatchReadme(string root)
    {
        var paths = new[] { "README.md", "README.rst", "README.adoc", "README.txt", "README" };
        foreach (var p in paths)
        {
            var fullPath = Path.Combine(root, p);
            if (File.Exists(fullPath))
            {
                return fullPath;
            }
        }
        return null;
    }

    private static void CheckReadmeSections(string content, string filePath, string rootPath, List<Finding> findings)
    {
        var installKeywords = new[] { "install", "installation", "getting started", "setup" };
        var usageKeywords = new[] { "usage", "example", "quick start", "how to use" };
        var quickStartKeywords = new[] { "quick start", "quickstart", "getting started" };

        var relativePath = Path.GetRelativePath(rootPath, filePath);

        if (!installKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding(
                "TRUST-REPO010",
                "README lacks installation guidance",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "README lacks installation guidance",
                [new Evidence("readme-content", "No installation keywords found in README.", relativePath)],
                new Recommendation("Add installation instructions or a 'getting started' section to the README.")));
        }

        if (!usageKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding(
                "TRUST-REPO011",
                "README lacks usage guidance",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "README lacks usage guidance",
                [new Evidence("readme-content", "No usage keywords found in README.", relativePath)],
                new Recommendation("Add usage instructions or examples to the README.")));
        }

        if (!quickStartKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding(
                "TRUST-REPO012",
                "README lacks quick start guidance",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "README lacks quick start guidance",
                [new Evidence("readme-content", "No quick start or getting started wording found in README.", relativePath)],
                new Recommendation("Add a short quick start section that helps users try the project quickly.")));
        }
    }

    private static void CheckReadmeLocalLinks(string content, string readmePath, string rootPath, List<Finding> findings)
    {
        var relativeReadmePath = Path.GetRelativePath(rootPath, readmePath);
        var readmeDirectory = Path.GetDirectoryName(readmePath) ?? rootPath;
        var reportedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in MarkdownLinkPattern().Matches(content))
        {
            var rawTarget = match.Groups["target"].Value.Trim();
            if (!IsLocalFileLink(rawTarget))
            {
                continue;
            }

            var targetWithoutAnchor = rawTarget.Split('#', 2)[0];
            if (string.IsNullOrWhiteSpace(targetWithoutAnchor))
            {
                continue;
            }

            if (!TryDecodeLinkTarget(targetWithoutAnchor, out var decodedTarget))
            {
                continue;
            }

            var normalizedTarget = decodedTarget.Replace('/', Path.DirectorySeparatorChar);
            var fullTarget = Path.GetFullPath(Path.Combine(readmeDirectory, normalizedTarget));
            var fullRoot = Path.GetFullPath(rootPath);
            if (!IsSameOrChildPath(fullRoot, fullTarget))
            {
                continue;
            }

            if (File.Exists(fullTarget) || Directory.Exists(fullTarget))
            {
                continue;
            }

            if (!reportedTargets.Add(rawTarget))
            {
                continue;
            }

            findings.Add(new Finding(
                "TRUST-REPO014",
                "README contains broken-looking local link",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "README contains broken-looking local link",
                [new Evidence("readme-link", $"Local README link target was not found: {rawTarget}", relativeReadmePath, GetLineNumber(content, match.Index))],
                new Recommendation("Fix or remove broken README links so users can follow documentation reliably.")));
        }
    }

    private static bool IsLocalFileLink(string target)
    {
        return !target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
               !target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
               !target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) &&
               !target.StartsWith("#", StringComparison.Ordinal) &&
               !target.StartsWith("tel:", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryDecodeLinkTarget(string target, out string decoded)
    {
        if (HasMalformedPercentEncoding(target))
        {
            decoded = string.Empty;
            return false;
        }

        try
        {
            decoded = Uri.UnescapeDataString(target);
            return true;
        }
        catch (UriFormatException)
        {
            decoded = string.Empty;
            return false;
        }
    }

    private static bool HasMalformedPercentEncoding(string target)
    {
        for (var index = 0; index < target.Length; index++)
        {
            if (target[index] != '%')
            {
                continue;
            }

            if (index + 2 >= target.Length ||
                !Uri.IsHexDigit(target[index + 1]) ||
                !Uri.IsHexDigit(target[index + 2]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSameOrChildPath(string rootPath, string candidatePath)
    {
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        var normalizedRoot = rootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedCandidate = candidatePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return normalizedCandidate.Equals(normalizedRoot, comparison) ||
               normalizedCandidate.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison) ||
               normalizedCandidate.StartsWith(normalizedRoot + Path.AltDirectorySeparatorChar, comparison);
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var index = 0; index < matchIndex && index < content.Length; index++)
        {
            if (content[index] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    private static void CheckRequiredFile(
        string root,
        IReadOnlyList<string> relativePaths,
        string ruleId,
        string title,
        string recommendation,
        List<Finding> findings,
        Severity severity)
    {
        if (relativePaths.Any(path => File.Exists(Path.Combine(root, path)) || Directory.Exists(Path.Combine(root, path))))
        {
            return;
        }

        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.RepositoryHealth,
            severity,
            Confidence.High,
            title,
            [new Evidence("file-missing", $"None of the expected paths exist: {string.Join(", ", relativePaths)}")],
            new Recommendation(recommendation)));
    }

    [GeneratedRegex(@"\[[^\]]+\]\((?<target>[^)]+)\)")]
    private static partial Regex MarkdownLinkPattern();
}
