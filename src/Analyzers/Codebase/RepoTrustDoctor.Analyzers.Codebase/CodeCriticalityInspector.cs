using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.Codebase;

internal static partial class CodeCriticalityInspector
{
    private const int LargeFileLineThreshold = 400;
    private const int BroadExceptionLookaheadLines = 24;

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
        new(CodeCriticalityReason.Deserialization, ["binaryformatter", "typenamehandling", "new objectinputstream", "pickle.load", "yaml.unsafe_load"]),
        new(CodeCriticalityReason.CommandExecution, ["process.start(", "runtime.exec(", "runtime.getruntime().exec(", "new processbuilder(", "subprocess.run(", "subprocess.popen(", "subprocess.call(", "subprocess.check_call(", "subprocess.check_output(", "os.system(", "os.popen(", "child_process.exec", "child_process.spawn", "execsync(", "spawnsync(", "command::new(", "popen("]),
        new(CodeCriticalityReason.JavaSerializationHook, ["readobject("])
    ];

    internal static CodeCriticalityFile Analyze(string repositoryPath, string filePath, string text)
    {
        var reasons = new HashSet<CodeCriticalityReason>();
        var firstRelevantLine = default(int?);
        var relevantLines = new Dictionary<CodeCriticalityReason, int>();
        var searchableText = RemoveAnalyzerVocabulary(RemoveComments(RemoveQuotedText(text)));
        var lower = searchableText.ToLowerInvariant();
        var lines = searchableText.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var group in KeywordGroups)
        {
            if (group.Reason == CodeCriticalityReason.CommandExecution)
            {
                var commandLine = FindFirstCommandExecutionLine(lines, group.Keywords);
                if (commandLine is null)
                {
                    continue;
                }

                reasons.Add(group.Reason);
                relevantLines[group.Reason] = commandLine.Value;
                firstRelevantLine ??= commandLine;
                continue;
            }

            if (group.Keywords.Any(keyword => lower.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                var line = FindFirstLine(lines, group.Keywords);
                reasons.Add(group.Reason);
                if (line is not null)
                {
                    relevantLines[group.Reason] = line.Value;
                }

                firstRelevantLine ??= line;
            }
        }

        var dynamicEvaluationLine = FindFirstDynamicEvaluationLine(filePath, lines);
        if (dynamicEvaluationLine is not null)
        {
            reasons.Add(CodeCriticalityReason.DynamicCodeEvaluation);
            relevantLines[CodeCriticalityReason.DynamicCodeEvaluation] = dynamicEvaluationLine.Value;
            firstRelevantLine ??= dynamicEvaluationLine;
        }

        if (lines.Length > LargeFileLineThreshold)
        {
            reasons.Add(CodeCriticalityReason.LargeFile);
        }

        var firstBroadExceptionLine = FindFirstBroadExceptionLine(lines);
        if (firstBroadExceptionLine is not null)
        {
            reasons.Add(CodeCriticalityReason.BroadExceptionHandling);
            relevantLines[CodeCriticalityReason.BroadExceptionHandling] = firstBroadExceptionLine.Value;
            firstRelevantLine ??= firstBroadExceptionLine;
        }

        SuppressStaticAnalyzerVocabulary(repositoryPath, filePath, text, reasons);

        var score = Math.Min(100, reasons.Sum(ScoreReason));
        return new CodeCriticalityFile(
            Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/'),
            score,
            lines.Length,
            reasons.OrderBy(reason => reason.ToString(), StringComparer.OrdinalIgnoreCase).ToArray(),
            firstRelevantLine,
            relevantLines);
    }

    private static int ScoreReason(CodeCriticalityReason reason) => reason switch
    {
        CodeCriticalityReason.Deserialization => 30,
        CodeCriticalityReason.CommandExecution => 30,
        CodeCriticalityReason.DynamicCodeEvaluation => 22,
        CodeCriticalityReason.JavaSerializationHook => 18,
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

    private static int? FindFirstCommandExecutionLine(string[] lines, IReadOnlyList<string> keywords)
    {
        for (var index = 0; index < lines.Length; index++)
        {
            if (!keywords.Any(keyword => lines[index].Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (IsBoundedProcessStartCall(lines, index))
            {
                continue;
            }

            return index + 1;
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

    private static int? FindFirstDynamicEvaluationLine(string filePath, string[] lines)
    {
        var pattern = Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".js" or ".jsx" or ".ts" or ".tsx" => JavaScriptDynamicEvaluationPattern(),
            ".py" or ".rb" => PythonRubyDynamicEvaluationPattern(),
            _ => null
        };

        if (pattern is null)
        {
            return null;
        }

        for (var index = 0; index < lines.Length; index++)
        {
            if (pattern.IsMatch(lines[index]))
            {
                return index + 1;
            }
        }

        return null;
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

    private static bool IsBoundedProcessStartCall(string[] lines, int lineIndex)
    {
        if (!ProcessInstanceStartPattern().IsMatch(lines[lineIndex]))
        {
            return false;
        }

        var start = Math.Max(0, lineIndex - 16);
        var length = Math.Min(lines.Length - start, 24);
        var localBlock = string.Join('\n', lines.Skip(start).Take(length));
        return localBlock.Contains("processstartinfo", StringComparison.OrdinalIgnoreCase) &&
               localBlock.Contains("useshellexecute = false", StringComparison.OrdinalIgnoreCase) &&
               localBlock.Contains("argumentlist.add", StringComparison.OrdinalIgnoreCase);
    }

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

        return ThrowsOrReraisesExceptionPattern().IsMatch(block) ||
               DiagnosticExceptionLoggingPattern().IsMatch(block) ||
               block.Contains("scanlifecyclestate.failed", StringComparison.OrdinalIgnoreCase) ||
               block.Contains("fail_json(", StringComparison.OrdinalIgnoreCase) ||
               block.Contains("response_for_exception", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"catch\s*\(\s*(Exception|System\.Exception|Throwable|Error)\b|except\s+(Exception|BaseException)\b|catch\s*\(\s*err\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex BroadExceptionRegex();

    [GeneratedRegex(@"^\s*(?:throw\s*(?:;|new\b|[A-Za-z_][\w.]*\s*;)|raise(?:\s|$))", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex ThrowsOrReraisesExceptionPattern();

    [GeneratedRegex(@"\b(?:logger|logging|log)\.exception\s*\(|\blogger\.logerror\s*\(|\blogerror\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex DiagnosticExceptionLoggingPattern();

    [GeneratedRegex("\"\"\"[\\s\\S]*?\"\"\"|@\"(?:[^\"]|\"\")*\"|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", RegexOptions.Multiline)]
    private static partial Regex QuotedTextRegex();

    [GeneratedRegex(@"/\*[\s\S]*?\*/", RegexOptions.Multiline)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"(?<![\w$])eval\s*\(|new\s+function\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex JavaScriptDynamicEvaluationPattern();

    [GeneratedRegex(@"(?<![\w.])eval\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex PythonRubyDynamicEvaluationPattern();

    [GeneratedRegex(@"CodeCriticalityReason\.\w+", RegexOptions.IgnoreCase)]
    private static partial Regex CodeCriticalityReasonReferenceRegex();

    [GeneratedRegex(@"\b(?:public\s+)?enum\s+CodeCriticalityReason\s*\{[\s\S]*?\}", RegexOptions.IgnoreCase)]
    private static partial Regex CodeCriticalityEnumDeclarationRegex();

    [GeneratedRegex(@"\b[A-Za-z_]\w*\.start\s*\(\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex ProcessInstanceStartPattern();

    private sealed record KeywordGroup(CodeCriticalityReason Reason, IReadOnlyList<string> Keywords);
}
