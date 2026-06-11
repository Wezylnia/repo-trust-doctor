using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class CodeCriticalityAnalyzer : IRepositoryAnalyzer
{
    private const int LargeFileLineThreshold = 400;
    private const int FindingLimit = 12;

    private static readonly string[] SourceExtensions = [".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".kt", ".rs"];

    private static readonly IReadOnlyList<KeywordGroup> KeywordGroups =
    [
        new(CodeCriticalityReason.Authentication, ["authenticate", "authentication", "login", "signin", "session", "jwt"]),
        new(CodeCriticalityReason.Authorization, ["authorize", "authorization", "permission", "role", "policy"]),
        new(CodeCriticalityReason.Payments, ["payment", "billing", "invoice", "stripe", "checkout", "refund"]),
        new(CodeCriticalityReason.Database, ["database", "dbcontext", "sql", "migration", "transaction", "repository"]),
        new(CodeCriticalityReason.FileSystem, ["file.", "filesystem", "readall", "writeall", "upload", "download"]),
        new(CodeCriticalityReason.Network, ["httpclient", "fetch(", "axios", "request", "socket", "webhook"]),
        new(CodeCriticalityReason.Cryptography, ["encrypt", "decrypt", "hash", "hmac", "rsa", "aes", "crypto"]),
        new(CodeCriticalityReason.Secrets, ["secret", "password", "token", "apikey", "api_key", "credential"]),
        new(CodeCriticalityReason.Deserialization, ["binaryformatter", "objectinputstream", "pickle.load", "yaml.unsafe_load", "xmlserializer", "deserialize", "unmarshal", "readobject"]),
        new(CodeCriticalityReason.CommandExecution, ["process.start", "runtime.exec", "subprocess", "os.system", "exec(", "eval(", "popen", "system("])
    ];

    public string Id => "codebase-02-criticality";

    public string DisplayName => "Code Criticality";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(20);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE004",
            "Security-sensitive code area was detected",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A source file appears to contain security-sensitive or operationally critical logic.",
            "Prioritize review and tests for files that handle auth, payments, data access, network calls, cryptography, secrets, or file operations."),
        new(
            "TRUST-CODE005",
            "Large critical source file was detected",
            AnalysisCategory.Codebase,
            Severity.Low,
            Confidence.Medium,
            "A critical source file is large enough to make review and change isolation harder.",
            "Split large critical files into smaller units or add targeted tests before risky changes."),
        new(
            "TRUST-CODE006",
            "Broad exception handling in critical code",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A critical source file uses broad exception handling that can hide failures.",
            "Catch specific exception types and preserve enough context for diagnosis and rollback."),
        new(
            "TRUST-CODE014",
            "Deserialization in critical code",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A source file uses deserialization APIs that are known vectors for remote code execution.",
            "Use safe deserialization methods, avoid BinaryFormatter, restrict allowed types, and validate deserialized input.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var criticalFiles = new List<CodeCriticalityFile>();

        foreach (var file in EnumerateSourceFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var analyzed = AnalyzeFile(context.RepositoryPath, file, text);
            if (analyzed.Score >= 30)
            {
                criticalFiles.Add(analyzed);
            }
        }

        var ordered = criticalFiles
            .OrderByDescending(file => file.Score)
            .ThenBy(file => file.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var findings = new List<Finding>();
        findings.AddRange(ordered
            .Where(file => file.Score >= 50)
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE004",
                Severity.Medium,
                "Security-sensitive code area was detected",
                $"{file.FilePath} has a code criticality score of {file.Score} from {FormatReasons(file.Reasons)}.",
                "code.criticality",
                file)));

        findings.AddRange(ordered
            .Where(file => file.LineCount > LargeFileLineThreshold && file.Reasons.Contains(CodeCriticalityReason.LargeFile))
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE005",
                Severity.Low,
                "Large critical source file was detected",
                $"{file.FilePath} has {file.LineCount.ToString(CultureInfo.InvariantCulture)} lines and critical code signals.",
                "code.large_file",
                file)));

        findings.AddRange(ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.BroadExceptionHandling))
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE006",
                Severity.Medium,
                "Broad exception handling in critical code",
                $"{file.FilePath} catches broad exceptions in critical code.",
                "code.broad_exception",
                file)));

        findings.AddRange(ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.Deserialization))
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE014",
                Severity.High,
                "Deserialization in critical code",
                $"{file.FilePath} uses deserialization APIs that may enable remote code execution.",
                "code.deserialization",
                file)));

        var artifact = new CodeCriticalityArtifact(
            ordered,
            new Dictionary<string, string>
            {
                ["code.criticality.file.count"] = ordered.Length.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.highest_score"] = (ordered.FirstOrDefault()?.Score ?? 0).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.large_file.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.LargeFile)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.broad_exception.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.BroadExceptionHandling)).ToString(CultureInfo.InvariantCulture)
            });

        return AnalyzerResult.Completed(findings, [new AnalyzerArtifact(CodeCriticalityArtifact.ArtifactKey, artifact)]);
    }

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => SourceExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase));

    private static CodeCriticalityFile AnalyzeFile(string repositoryPath, string filePath, string text)
    {
        var reasons = new HashSet<CodeCriticalityReason>();
        var firstRelevantLine = default(int?);
        var lower = text.ToLowerInvariant();
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var group in KeywordGroups)
        {
            if (group.Keywords.Any(keyword => lower.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add(group.Reason);
                firstRelevantLine ??= FindFirstLine(lines, group.Keywords);
            }
        }

        if (lines.Length > LargeFileLineThreshold)
        {
            reasons.Add(CodeCriticalityReason.LargeFile);
        }

        if (BroadExceptionRegex().IsMatch(text))
        {
            reasons.Add(CodeCriticalityReason.BroadExceptionHandling);
            firstRelevantLine ??= FindFirstBroadExceptionLine(lines);
        }

        var score = Math.Min(100, reasons.Sum(ScoreReason));
        return new CodeCriticalityFile(
            Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/'),
            score,
            lines.Length,
            reasons.OrderBy(reason => reason.ToString(), StringComparer.OrdinalIgnoreCase).ToArray(),
            firstRelevantLine);
    }

    private static int ScoreReason(CodeCriticalityReason reason) => reason switch
    {
        CodeCriticalityReason.Deserialization => 30,
        CodeCriticalityReason.CommandExecution => 28,
        CodeCriticalityReason.Authentication or
        CodeCriticalityReason.Authorization or
        CodeCriticalityReason.Payments or
        CodeCriticalityReason.Cryptography or
        CodeCriticalityReason.Secrets => 25,
        CodeCriticalityReason.Database or
        CodeCriticalityReason.Network or
        CodeCriticalityReason.FileSystem => 18,
        CodeCriticalityReason.BroadExceptionHandling => 16,
        CodeCriticalityReason.LargeFile => 12,
        _ => 10
    };

    private static int? FindFirstLine(string[] lines, IReadOnlyList<string> keywords)
    {
        for (var index = 0; index < lines.Length; index++)
        {
            if (keywords.Any(keyword => lines[index].Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                return index + 1;
            }
        }

        return null;
    }

    private static int? FindFirstBroadExceptionLine(string[] lines)
    {
        for (var index = 0; index < lines.Length; index++)
        {
            if (BroadExceptionRegex().IsMatch(lines[index]))
            {
                return index + 1;
            }
        }

        return null;
    }

    private static Finding CreateCriticalityFinding(
        string ruleId,
        Severity severity,
        string title,
        string message,
        string evidenceKind,
        CodeCriticalityFile file) =>
        new(
            ruleId,
            title,
            AnalysisCategory.Codebase,
            severity,
            Confidence.Medium,
            message,
            [new Evidence(evidenceKind, message, file.FilePath, file.FirstRelevantLine)],
            new Recommendation("Review critical code files with extra care and ensure their behavior is covered by targeted tests."),
            Tags: ["codebase", "criticality"]);

    private static string FormatReasons(IReadOnlyList<CodeCriticalityReason> reasons) =>
        string.Join(", ", reasons.Select(reason => reason.ToString()));

    [GeneratedRegex(@"catch\s*\(\s*(Exception|System\.Exception|Throwable|Error)\b|except\s+(Exception|BaseException)\b|catch\s*\(\s*err\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex BroadExceptionRegex();

    private sealed record KeywordGroup(CodeCriticalityReason Reason, IReadOnlyList<string> Keywords);
}
