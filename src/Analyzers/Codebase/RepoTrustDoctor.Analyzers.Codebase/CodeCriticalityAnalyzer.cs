using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class CodeCriticalityAnalyzer : IRepositoryAnalyzer
{
    private const int LargeFileLineThreshold = 400;
    private const int FindingLimit = 12;
    private const int BroadExceptionLookaheadLines = 24;

    private static readonly string[] SourceExtensions = [".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".kt", ".rs"];

    private static readonly IReadOnlyList<KeywordGroup> KeywordGroups =
    [
        new(CodeCriticalityReason.Authentication, ["authenticate", "authentication", "login", "signin", "session", "jwt"]),
        new(CodeCriticalityReason.Authorization, ["authorize", "authorization", "permission", "requireauthorization", "allowanonymous"]),
        new(CodeCriticalityReason.Payments, ["payment", "billing", "invoice", "stripe", "refund", "cardnumber", "card_number"]),
        new(CodeCriticalityReason.Database, ["database", "dbcontext", "sqlconnection", "npgsql", "mysql", "postgres", "migrationbuilder", "transaction"]),
        new(CodeCriticalityReason.FileSystem, ["file.", "filesystem", "readall", "writeall", "upload", "download"]),
        new(CodeCriticalityReason.Network, ["httpclient", "httpcontext", "httpget", "httppost", "fetch(", "axios", "socket", "webhook"]),
        new(CodeCriticalityReason.Cryptography, ["encrypt", "decrypt", "sha256", "sha512", "hmac", "rsa", "aes", "crypto"]),
        new(CodeCriticalityReason.Secrets, ["secret", "password", "access_token", "refresh_token", "bearer", "apikey", "api_key", "credential"]),
        new(CodeCriticalityReason.Deserialization, ["binaryformatter", "typenamehandling", "objectinputstream", "pickle.load", "yaml.unsafe_load", "readobject"]),
        new(CodeCriticalityReason.CommandExecution, ["process.start", "runtime.exec", "subprocess.", "os.system", "child_process", "execsync", "spawnsync", "command::new", "eval(", "popen"])
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
            "Use safe deserialization methods, avoid BinaryFormatter, restrict allowed types, and validate deserialized input."),
        new(
            "TRUST-CODE015",
            "Command execution in critical code",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A source file invokes command execution APIs that can run operating-system commands.",
            "Avoid shell execution for untrusted input; use safe APIs, allowlists, and explicit argument boundaries.")
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
            if (analyzed.Score >= 30 ||
                analyzed.Reasons.Contains(CodeCriticalityReason.CommandExecution) ||
                analyzed.Reasons.Contains(CodeCriticalityReason.Deserialization))
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
                file,
                "Use safe deserialization methods, avoid BinaryFormatter, restrict allowed types, and validate deserialized input.")));

        findings.AddRange(ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution))
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE015",
                Severity.High,
                "Command execution in critical code",
                $"{file.FilePath} invokes command execution APIs that can run operating-system commands.",
                "code.command_execution",
                file,
                "Avoid shell execution for untrusted input; use safe APIs, allowlists, and explicit argument boundaries.")));

        var artifact = new CodeCriticalityArtifact(
            ordered,
            new Dictionary<string, string>
            {
                ["code.criticality.file.count"] = ordered.Length.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.highest_score"] = (ordered.FirstOrDefault()?.Score ?? 0).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.large_file.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.LargeFile)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.broad_exception.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.BroadExceptionHandling)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.deserialization.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.Deserialization)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.command_execution.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution)).ToString(CultureInfo.InvariantCulture)
            });

        return AnalyzerResult.Completed(findings, [new AnalyzerArtifact(CodeCriticalityArtifact.ArtifactKey, artifact)]);
    }

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => SourceExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !IsTestSource(root, file));

    private static CodeCriticalityFile AnalyzeFile(string repositoryPath, string filePath, string text)
    {
        var reasons = new HashSet<CodeCriticalityReason>();
        var firstRelevantLine = default(int?);
        var searchableText = RemoveAnalyzerVocabulary(RemoveComments(RemoveQuotedText(text)));
        var lower = searchableText.ToLowerInvariant();
        var lines = searchableText.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var group in KeywordGroups)
        {
            if (group.Reason == CodeCriticalityReason.CommandExecution &&
                HasBoundedProcessInvocation(lower))
            {
                continue;
            }

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

        var firstBroadExceptionLine = FindFirstBroadExceptionLine(lines);
        if (firstBroadExceptionLine is not null)
        {
            reasons.Add(CodeCriticalityReason.BroadExceptionHandling);
            firstRelevantLine ??= firstBroadExceptionLine;
        }

        SuppressStaticAnalyzerVocabulary(repositoryPath, filePath, text, reasons);

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
        CodeCriticalityReason.CommandExecution => 30,
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
            if (IsBroadExceptionLine(lines[index]) &&
                !IsBoundedBroadExceptionHandler(lines, index))
            {
                return index + 1;
            }
        }

        return null;
    }

    private static bool IsTestSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath);
    }

    private static void SuppressStaticAnalyzerVocabulary(
        string root,
        string filePath,
        string originalText,
        HashSet<CodeCriticalityReason> reasons)
    {
        if (!IsStaticAnalyzerImplementation(root, filePath, originalText))
        {
            return;
        }

        reasons.Remove(CodeCriticalityReason.Authentication);
        reasons.Remove(CodeCriticalityReason.Authorization);
        reasons.Remove(CodeCriticalityReason.Payments);
        reasons.Remove(CodeCriticalityReason.Database);
        reasons.Remove(CodeCriticalityReason.FileSystem);
        reasons.Remove(CodeCriticalityReason.Network);
        reasons.Remove(CodeCriticalityReason.Cryptography);
        reasons.Remove(CodeCriticalityReason.Secrets);
    }

    private static bool IsStaticAnalyzerImplementation(string root, string filePath, string originalText)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return relativePath.Contains("/Analyzers/", StringComparison.OrdinalIgnoreCase) ||
               originalText.Contains("IRepositoryAnalyzer", StringComparison.Ordinal) ||
               originalText.Contains("IDependencyInventoryCollector", StringComparison.Ordinal);
    }

    private static string RemoveQuotedText(string text) =>
        QuotedTextRegex().Replace(text, match =>
        {
            var newlineCount = match.Value.Count(character => character == '\n');
            return newlineCount == 0 ? string.Empty : new string('\n', newlineCount);
        });

    private static string RemoveAnalyzerVocabulary(string text) =>
        CodeCriticalityEnumDeclarationRegex().Replace(
            CodeCriticalityReasonReferenceRegex().Replace(text, string.Empty),
            match =>
            {
                var newlineCount = match.Value.Count(character => character == '\n');
                return newlineCount == 0 ? string.Empty : new string('\n', newlineCount);
            });

    private static string RemoveComments(string text) =>
        LineCommentRegex().Replace(
            BlockCommentRegex().Replace(text, match =>
            {
                var newlineCount = match.Value.Count(character => character == '\n');
                return newlineCount == 0 ? string.Empty : new string('\n', newlineCount);
            }),
            string.Empty);

    private static bool HasBoundedProcessInvocation(string searchableText) =>
        searchableText.Contains("processstartinfo", StringComparison.OrdinalIgnoreCase) &&
        searchableText.Contains("useshellexecute = false", StringComparison.OrdinalIgnoreCase) &&
        searchableText.Contains("argumentlist.add", StringComparison.OrdinalIgnoreCase);

    private static bool IsBroadExceptionLine(string line) =>
        BroadExceptionRegex().IsMatch(line) &&
        !line.Contains(" when (", StringComparison.OrdinalIgnoreCase);

    private static bool IsBoundedBroadExceptionHandler(string[] lines, int catchLineIndex)
    {
        var block = string.Join(
            '\n',
            lines
                .Skip(catchLineIndex)
                .Take(BroadExceptionLookaheadLines));

        return block.Contains("throw;", StringComparison.OrdinalIgnoreCase) ||
               block.Contains("logerror", StringComparison.OrdinalIgnoreCase) ||
               block.Contains("scanlifecyclestate.failed", StringComparison.OrdinalIgnoreCase);
    }

    private static Finding CreateCriticalityFinding(
        string ruleId,
        Severity severity,
        string title,
        string message,
        string evidenceKind,
        CodeCriticalityFile file,
        string recommendation = "Review critical code files with extra care and ensure their behavior is covered by targeted tests.") =>
        new(
            ruleId,
            title,
            AnalysisCategory.Codebase,
            severity,
            Confidence.Medium,
            message,
            [new Evidence(evidenceKind, message, file.FilePath, file.FirstRelevantLine)],
            new Recommendation(recommendation),
            Tags: ["codebase", "criticality"]);

    private static string FormatReasons(IReadOnlyList<CodeCriticalityReason> reasons) =>
        string.Join(", ", reasons.Select(reason => reason.ToString()));

    [GeneratedRegex(@"catch\s*\(\s*(Exception|System\.Exception|Throwable|Error)\b|except\s+(Exception|BaseException)\b|catch\s*\(\s*err\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex BroadExceptionRegex();

    [GeneratedRegex("\"\"\"[\\s\\S]*?\"\"\"|@\"(?:[^\"]|\"\")*\"|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", RegexOptions.Multiline)]
    private static partial Regex QuotedTextRegex();

    [GeneratedRegex(@"/\*[\s\S]*?\*/", RegexOptions.Multiline)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"CodeCriticalityReason\.\w+", RegexOptions.IgnoreCase)]
    private static partial Regex CodeCriticalityReasonReferenceRegex();

    [GeneratedRegex(@"\b(?:public\s+)?enum\s+CodeCriticalityReason\s*\{[\s\S]*?\}", RegexOptions.IgnoreCase)]
    private static partial Regex CodeCriticalityEnumDeclarationRegex();

    private sealed record KeywordGroup(CodeCriticalityReason Reason, IReadOnlyList<string> Keywords);
}
