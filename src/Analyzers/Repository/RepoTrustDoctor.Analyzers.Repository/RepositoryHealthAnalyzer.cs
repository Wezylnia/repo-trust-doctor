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
        new("TRUST-REPO020", "CODEOWNERS does not cover sensitive repository areas", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "CODEOWNERS exists but important repository areas may not be covered.", "Add CODEOWNERS entries for CI, release, infrastructure, and package manifest paths."),
        new("TRUST-REPO021", "SECURITY policy lacks vulnerability reporting instructions", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "SECURITY.md exists but vulnerability reporting instructions were not observed.", "Add clear vulnerability reporting instructions to SECURITY.md."),
        new("TRUST-REPO022", "SECURITY policy lacks supported version information", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "SECURITY.md exists but supported version information was not observed.", "Document supported versions in SECURITY.md."),
        new("TRUST-REPO023", "Toolchain version is not pinned", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium, "A project ecosystem file exists but no toolchain version pinning was observed.", "Pin the toolchain version with .nvmrc, .node-version, .tool-versions, global.json, rust-toolchain.toml, or equivalent."),
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

        // REP020: CODEOWNERS coverage of sensitive areas
        CheckCodeownersCoverage(context.RepositoryPath, findings);

        // REP021-REP022: SECURITY.md quality
        CheckSecurityPolicyQuality(context.RepositoryPath, findings);

        // REP023: Toolchain pinning
        CheckToolchainPinning(context.RepositoryPath, findings);

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

    // --- REP020: CODEOWNERS coverage ---

    private static readonly string[] SensitivePaths =
    [
        ".github/workflows/", ".github/actions/", "Dockerfile", "docker-compose.yml",
        "compose.yml", "k8s/", "deploy/", "charts/", "terraform/", "infra/",
        "src/", "package.json", "*.csproj", "*.sln", "*.slnx"
    ];

    private static void CheckCodeownersCoverage(string root, List<Finding> findings)
    {
        var codeownersPath = FindCodeownersPath(root);
        if (codeownersPath is null)
        {
            return; // REP006 already covers missing CODEOWNERS
        }

        if (!RepositoryFileSystem.CanReadAsText(codeownersPath))
        {
            return;
        }

        var content = File.ReadAllText(codeownersPath);
        var ownedPatterns = ParseCodeownersPatterns(content);

        var uncoveredSensitive = SensitivePaths
            .Where(sensitive =>
            {
                var exists = SensitivePathExists(root, sensitive);

                if (!exists) return false;

                return !ownedPatterns.Any(owned => PathMatchesCodeownersPattern(sensitive, owned));
            })
            .Take(10)
            .ToArray();

        if (uncoveredSensitive.Length > 0)
        {
            var ciUncovered = uncoveredSensitive.Any(p =>
                p.Contains("workflows", StringComparison.OrdinalIgnoreCase) ||
                p.Contains("Dockerfile", StringComparison.OrdinalIgnoreCase) ||
                p.Contains("docker-compose", StringComparison.OrdinalIgnoreCase));

            findings.Add(new Finding(
                "TRUST-REPO020",
                "CODEOWNERS does not cover sensitive repository areas",
                AnalysisCategory.RepositoryHealth,
                ciUncovered ? Severity.Medium : Severity.Low,
                Confidence.Medium,
                "CODEOWNERS exists but important repository areas may not be covered.",
                [new Evidence("codeowners-coverage", $"Uncovered sensitive paths: {string.Join(", ", uncoveredSensitive)}", Path.GetRelativePath(root, codeownersPath))],
                new Recommendation("Add CODEOWNERS entries for CI, release, infrastructure, and package manifest paths."),
                IdentityKey: "rep020|codeowners-sensitive-coverage"));
        }
    }

    private static string? FindCodeownersPath(string root)
    {
        var paths = new[] { ".github/CODEOWNERS", "CODEOWNERS" };
        foreach (var p in paths)
        {
            var full = Path.Combine(root, p);
            if (File.Exists(full)) return full;
        }
        return null;
    }

    private static bool SensitivePathExists(string root, string sensitivePath)
    {
        if (sensitivePath.Contains('*'))
        {
            return RepositoryFileSystem.EnumerateFiles(root, sensitivePath).Any();
        }

        if (string.Equals(sensitivePath, "package.json", StringComparison.OrdinalIgnoreCase))
        {
            return RepositoryFileSystem.EnumerateFiles(root, sensitivePath).Any();
        }

        return File.Exists(Path.Combine(root, sensitivePath)) ||
               Directory.Exists(Path.Combine(root, sensitivePath));
    }

    private static HashSet<string> ParseCodeownersPatterns(string content)
    {
        var patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in content.Split('\n', '\r'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
            {
                continue;
            }

            // CODEOWNERS format: pattern @owner1 @owner2 ...
            var firstSpace = trimmed.IndexOf(' ');
            if (firstSpace > 0)
            {
                var pattern = trimmed[..firstSpace].Trim();
                if (!string.IsNullOrWhiteSpace(pattern) && pattern != "*")
                {
                    patterns.Add(pattern);
                }
            }
        }
        return patterns;
    }

    private static bool PathMatchesCodeownersPattern(string sensitivePath, string codeownersPattern)
    {
        // Simple prefix matching
        return sensitivePath.StartsWith(codeownersPattern.TrimEnd('*', '/'), StringComparison.OrdinalIgnoreCase) ||
               codeownersPattern.TrimEnd('*', '/').StartsWith(sensitivePath.TrimEnd('*', '/'), StringComparison.OrdinalIgnoreCase);
    }

    // --- REP021-REP022: SECURITY.md quality ---

    private static void CheckSecurityPolicyQuality(string root, List<Finding> findings)
    {
        var securityPath = FindSecurityPath(root);
        if (securityPath is null)
        {
            return; // REP003 already covers missing SECURITY.md
        }

        if (!RepositoryFileSystem.CanReadAsText(securityPath))
        {
            return;
        }

        var content = File.ReadAllText(securityPath);
        var relativePath = Path.GetRelativePath(root, securityPath);

        // REP021: Reporting instructions
        var reportingTokens = new[]
        {
            "email", "security advisory", "GitHub Security Advisory",
            "security contact", "disclosure", "report a vulnerability"
        };
        var hasReporting = reportingTokens.Any(t => content.Contains(t, StringComparison.OrdinalIgnoreCase)) ||
                          ContainsEmailLike(content);

        if (!hasReporting)
        {
            findings.Add(new Finding(
                "TRUST-REPO021",
                "SECURITY policy lacks vulnerability reporting instructions",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "SECURITY.md exists but vulnerability reporting instructions were not observed.",
                [new Evidence("security-policy", "No vulnerability reporting instructions found in SECURITY.md.", relativePath)],
                new Recommendation("Add clear vulnerability reporting instructions to SECURITY.md."),
                IdentityKey: "rep021|security-policy-reporting"));
        }

        // REP022: Supported versions
        var versionTokens = new[]
        {
            "supported versions", "currently supported", "security updates"
        };
        var hasVersionInfo = versionTokens.Any(t => content.Contains(t, StringComparison.OrdinalIgnoreCase)) ||
                            ContainsVersionTable(content);

        if (!hasVersionInfo)
        {
            findings.Add(new Finding(
                "TRUST-REPO022",
                "SECURITY policy lacks supported version information",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                "SECURITY.md exists but supported version information was not observed.",
                [new Evidence("security-policy", "No supported version information found in SECURITY.md.", relativePath)],
                new Recommendation("Document supported versions in SECURITY.md."),
                IdentityKey: "rep022|security-policy-supported-versions"));
        }
    }

    private static string? FindSecurityPath(string root)
    {
        var paths = new[] { "SECURITY.md", ".github/SECURITY.md" };
        foreach (var p in paths)
        {
            var full = Path.Combine(root, p);
            if (File.Exists(full)) return full;
        }
        return null;
    }

    private static bool ContainsEmailLike(string content)
    {
        // Simple heuristic: contains something@something
        return Regex.IsMatch(content, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b");
    }

    private static bool ContainsVersionTable(string content)
    {
        // Simple heuristic: markdown table with version-like cells
        return content.Contains("|", StringComparison.Ordinal) &&
               (content.Contains("version", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(content, @"\|\s*\d+\.\d+"));
    }

    // --- REP023: Toolchain version pinning ---

    private static void CheckToolchainPinning(string root, List<Finding> findings)
    {
        // Node.js: package.json exists but no version pin
        if (RepositoryFileSystem.EnumerateFiles(root, "package.json").Any())
        {
            var hasNodePin = new[] { ".nvmrc", ".node-version", ".tool-versions", "mise.toml" }
                .Any(f => File.Exists(Path.Combine(root, f)));
            // packageManager field in package.json also counts
            if (!hasNodePin)
            {
                findings.Add(new Finding(
                    "TRUST-REPO023",
                    "Toolchain version is not pinned",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "A Node.js project exists but no Node version pinning was observed.",
                    [new Evidence("toolchain", "No .nvmrc, .node-version, .tool-versions, mise.toml, or packageManager field found.")],
                    new Recommendation("Pin the Node.js version with .nvmrc, .node-version, .tool-versions, or mise.toml."),
                    IdentityKey: "rep023|npm"));
            }
        }

        // .NET: csproj/sln exists but no global.json
        if (RepositoryFileSystem.EnumerateFiles(root, "*.csproj").Any() ||
            RepositoryFileSystem.EnumerateFiles(root, "*.sln").Any() ||
            RepositoryFileSystem.EnumerateFiles(root, "*.slnx").Any())
        {
            if (!File.Exists(Path.Combine(root, "global.json")))
            {
                findings.Add(new Finding(
                    "TRUST-REPO023",
                    "Toolchain version is not pinned",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "A .NET project exists but no global.json was found.",
                    [new Evidence("toolchain", "No global.json found at repository root.")],
                    new Recommendation("Pin the .NET SDK version with a global.json file."),
                    IdentityKey: "rep023|dotnet"));
            }
        }

        // Rust: Cargo.toml exists but no rust-toolchain.toml
        if (RepositoryFileSystem.EnumerateFiles(root, "Cargo.toml").Any())
        {
            var hasRustPin = new[] { "rust-toolchain.toml", ".tool-versions", "mise.toml" }
                .Any(f => File.Exists(Path.Combine(root, f)));
            if (!hasRustPin)
            {
                findings.Add(new Finding(
                    "TRUST-REPO023",
                    "Toolchain version is not pinned",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "A Rust project exists but no toolchain version pinning was observed.",
                    [new Evidence("toolchain", "No rust-toolchain.toml, .tool-versions, or mise.toml found.")],
                    new Recommendation("Pin the Rust toolchain version with rust-toolchain.toml or .tool-versions."),
                    IdentityKey: "rep023|cargo"));
            }
        }

        // Python: pyproject.toml/requirements.txt exists but no .python-version
        if (RepositoryFileSystem.EnumerateFiles(root, "pyproject.toml").Any() ||
            RepositoryFileSystem.EnumerateFiles(root, "requirements.txt").Any())
        {
            var hasPythonPin = new[] { ".python-version", ".tool-versions", "mise.toml" }
                .Any(f => File.Exists(Path.Combine(root, f)));
            if (!hasPythonPin)
            {
                findings.Add(new Finding(
                    "TRUST-REPO023",
                    "Toolchain version is not pinned",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "A Python project exists but no Python version pinning was observed.",
                    [new Evidence("toolchain", "No .python-version, .tool-versions, or mise.toml found.")],
                    new Recommendation("Pin the Python version with .python-version or .tool-versions."),
                    IdentityKey: "rep023|python"));
            }
        }

        // Ruby: Gemfile exists but no .ruby-version
        if (RepositoryFileSystem.EnumerateFiles(root, "Gemfile").Any())
        {
            var hasRubyPin = new[] { ".ruby-version", ".tool-versions", "mise.toml" }
                .Any(f => File.Exists(Path.Combine(root, f)));
            if (!hasRubyPin)
            {
                findings.Add(new Finding(
                    "TRUST-REPO023",
                    "Toolchain version is not pinned",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "A Ruby project exists but no Ruby version pinning was observed.",
                    [new Evidence("toolchain", "No .ruby-version, .tool-versions, or mise.toml found.")],
                    new Recommendation("Pin the Ruby version with .ruby-version or .tool-versions."),
                    IdentityKey: "rep023|ruby"));
            }
        }
    }
}
