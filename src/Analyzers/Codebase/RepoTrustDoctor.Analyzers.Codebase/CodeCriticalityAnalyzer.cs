using System.Globalization;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed class CodeCriticalityAnalyzer : IRepositoryAnalyzer
{
    private const int LargeFileLineThreshold = 400;
    private const int FindingLimit = 12;
    private const int JavaSerializationHookFindingLimit = 6;
    private const int MaxAnalyzedSourceFiles = 6000;

    private static readonly string[] SourceExtensions = [".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".kt", ".rs"];

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
            "Avoid shell execution for untrusted input; use safe APIs, allowlists, and explicit argument boundaries."),
        new(
            "TRUST-CODE016",
            "Dynamic code evaluation in critical code",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A source file dynamically evaluates code at runtime.",
            "Avoid eval-style APIs for untrusted input and keep dynamic module loading tightly bounded."),
        new(
            "TRUST-CODE017",
            "Java serialization hook in critical code",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A Java source file defines a custom readObject serialization hook in critical code.",
            "Review custom serialization hooks and validate any data restored during deserialization.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var criticalFiles = new List<CodeCriticalityFile>();

        var sourceFiles = EnumerateSourceFiles(context.RepositoryPath).ToArray();
        var selection = CodebaseFileSelection.Select(
            context.RepositoryPath,
            sourceFiles,
            MaxAnalyzedSourceFiles,
            file => GetSourcePriority(context.RepositoryPath, file));
        var analyzedFiles = selection.Files;

        foreach (var file in analyzedFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var analyzed = CodeCriticalityInspector.Analyze(context.RepositoryPath, file, text);
            if (analyzed.Score >= 30 ||
                analyzed.Reasons.Contains(CodeCriticalityReason.CommandExecution) ||
                analyzed.Reasons.Contains(CodeCriticalityReason.DynamicCodeEvaluation) ||
                analyzed.Reasons.Contains(CodeCriticalityReason.Deserialization) ||
                analyzed.Reasons.Contains(CodeCriticalityReason.JavaSerializationHook))
            {
                criticalFiles.Add(analyzed);
            }
        }

        var ordered = criticalFiles
            .OrderByDescending(file => file.Score)
            .ThenBy(file => file.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var code004Matches = ordered
            .Where(file => file.Score >= 50 && !IsToolingOrAnalyzerPath(file.FilePath))
            .ToArray();
        var code005Matches = ordered
            .Where(file => file.LineCount > LargeFileLineThreshold && file.Reasons.Contains(CodeCriticalityReason.LargeFile) && !IsToolingOrAnalyzerPath(file.FilePath))
            .ToArray();
        var code006Matches = ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.BroadExceptionHandling) && !IsToolingOrAnalyzerPath(file.FilePath))
            .ToArray();
        var code014Matches = ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.Deserialization))
            .ToArray();
        var code015Matches = ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution))
            .ToArray();
        var code016Matches = ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.DynamicCodeEvaluation))
            .ToArray();
        var code017Matches = ordered
            .Where(file => file.Reasons.Contains(CodeCriticalityReason.JavaSerializationHook) &&
                           !file.Reasons.Contains(CodeCriticalityReason.Deserialization))
            .ToArray();

        var findings = new List<Finding>();
        findings.AddRange(code004Matches
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE004",
                Severity.Medium,
                "Security-sensitive code area was detected",
                $"{file.FilePath} has a code criticality score of {file.Score} from {FormatReasons(file.Reasons)}.",
                "code.criticality",
                file)));

        findings.AddRange(code005Matches
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE005",
                Severity.Low,
                "Large critical source file was detected",
                $"{file.FilePath} has {file.LineCount.ToString(CultureInfo.InvariantCulture)} lines and critical code signals.",
                "code.large_file",
                file)));

        findings.AddRange(code006Matches
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE006",
                Severity.Medium,
                "Broad exception handling in critical code",
                $"{file.FilePath} catches broad exceptions in critical code.",
                "code.broad_exception",
                file)));

        findings.AddRange(code014Matches
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE014",
                Severity.High,
                "Deserialization in critical code",
                $"{file.FilePath} uses deserialization APIs that may enable remote code execution.",
                "code.deserialization",
                file,
                "Use safe deserialization methods, avoid BinaryFormatter, restrict allowed types, and validate deserialized input.")));

        findings.AddRange(code015Matches
            .Take(FindingLimit)
            .Select(file => CreateCommandExecutionFinding(context.RepositoryPath, file)));

        findings.AddRange(code016Matches
            .Take(FindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE016",
                Severity.Medium,
                "Dynamic code evaluation in critical code",
                $"{file.FilePath} dynamically evaluates code at runtime.",
                "code.dynamic_evaluation",
                file,
                "Avoid eval-style APIs for untrusted input and keep dynamic module loading tightly bounded.")));

        findings.AddRange(code017Matches
            .Take(JavaSerializationHookFindingLimit)
            .Select(file => CreateCriticalityFinding(
                "TRUST-CODE017",
                Severity.Medium,
                "Java serialization hook in critical code",
                $"{file.FilePath} defines a Java readObject serialization hook in critical code.",
                "code.java_serialization_hook",
                file,
                "Review custom serialization hooks and validate any data restored during deserialization.")));

        var artifact = new CodeCriticalityArtifact(
            ordered,
            new Dictionary<string, string>
            {
                ["code.criticality.source_file.count"] = sourceFiles.Length.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.analyzed_file.count"] = analyzedFiles.Count.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.truncated"] = (sourceFiles.Length > analyzedFiles.Count).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.partition.count"] = selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.selected_partition.count"] = selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.file.count"] = ordered.Length.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.highest_score"] = (ordered.FirstOrDefault()?.Score ?? 0).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.large_file.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.LargeFile)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.broad_exception.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.BroadExceptionHandling)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.deserialization.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.Deserialization)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.command_execution.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.dynamic_code_evaluation.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.DynamicCodeEvaluation)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.java_serialization_hook.count"] = ordered.Count(file => file.Reasons.Contains(CodeCriticalityReason.JavaSerializationHook)).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.finding.matched.count"] = CountCriticalityFindingMatches(code004Matches, code005Matches, code006Matches, code014Matches, code015Matches, code016Matches, code017Matches).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.finding.reported.count"] = findings.Count.ToString(CultureInfo.InvariantCulture),
                ["code.criticality.finding.suppressed.count"] = CountSuppressedCriticalityFindings(code004Matches, code005Matches, code006Matches, code014Matches, code015Matches, code016Matches, code017Matches).ToString(CultureInfo.InvariantCulture),
                ["code.criticality.finding.truncated"] = (CountSuppressedCriticalityFindings(code004Matches, code005Matches, code006Matches, code014Matches, code015Matches, code016Matches, code017Matches) > 0).ToString(CultureInfo.InvariantCulture)
            });

        var warnings = new List<string>();
        if (sourceFiles.Length > analyzedFiles.Count)
        {
            warnings.Add($"Code criticality analyzed {analyzedFiles.Count.ToString(CultureInfo.InvariantCulture)} of {sourceFiles.Length.ToString(CultureInfo.InvariantCulture)} source files, balanced across {selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture)} of {selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture)} repository partitions.");
        }

        var suppressedFindings = CountSuppressedCriticalityFindings(code004Matches, code005Matches, code006Matches, code014Matches, code015Matches, code016Matches, code017Matches);
        if (suppressedFindings > 0)
        {
            warnings.Add($"Code criticality findings were truncated after reporting {findings.Count.ToString(CultureInfo.InvariantCulture)} of {CountCriticalityFindingMatches(code004Matches, code005Matches, code006Matches, code014Matches, code015Matches, code016Matches, code017Matches).ToString(CultureInfo.InvariantCulture)} matches.");
        }

        return AnalyzerResult.Completed(findings, [new AnalyzerArtifact(CodeCriticalityArtifact.ArtifactKey, artifact)], warnings: warnings);
    }

    private static int CountCriticalityFindingMatches(params CodeCriticalityFile[][] groups) =>
        groups.Sum(group => group.Length);

    private static int CountSuppressedCriticalityFindings(
        CodeCriticalityFile[] code004Matches,
        CodeCriticalityFile[] code005Matches,
        CodeCriticalityFile[] code006Matches,
        CodeCriticalityFile[] code014Matches,
        CodeCriticalityFile[] code015Matches,
        CodeCriticalityFile[] code016Matches,
        CodeCriticalityFile[] code017Matches) =>
        CountSuppressed(code004Matches.Length, FindingLimit) +
        CountSuppressed(code005Matches.Length, FindingLimit) +
        CountSuppressed(code006Matches.Length, FindingLimit) +
        CountSuppressed(code014Matches.Length, FindingLimit) +
        CountSuppressed(code015Matches.Length, FindingLimit) +
        CountSuppressed(code016Matches.Length, FindingLimit) +
        CountSuppressed(code017Matches.Length, JavaSerializationHookFindingLimit);

    private static int CountSuppressed(int matched, int limit) => Math.Max(0, matched - limit);

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => SourceExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !IsTestSource(root, file));

    private static int GetSourcePriority(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        var classification = RepositoryPathClassifier.Classify(relativePath);
        return classification.HasAny(RepositoryPathClassification.Tooling | RepositoryPathClassification.AnalyzerImplementation)
            ? 1
            : 0;
    }

    private static bool IsTestSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath);
    }

    private static bool IsToolingOrAnalyzerPath(string relativePath) =>
        RepositoryPathClassifier.Classify(relativePath).HasAny(
            RepositoryPathClassification.Tooling |
            RepositoryPathClassification.AnalyzerImplementation);

    private static Finding CreateCriticalityFinding(
        string ruleId,
        Severity severity,
        string title,
        string message,
        string evidenceKind,
        CodeCriticalityFile file,
        string recommendation = "Review critical code files with extra care and ensure their behavior is covered by targeted tests.",
        Confidence confidence = Confidence.Medium) =>
        new(
            ruleId,
            title,
            AnalysisCategory.Codebase,
            severity,
            confidence,
            message,
            [new Evidence(evidenceKind, message, file.FilePath, GetRelevantLine(file, evidenceKind))],
            new Recommendation(recommendation),
            Tags: ["codebase", "criticality"]);

    private static Finding CreateCommandExecutionFinding(string repositoryPath, CodeCriticalityFile file)
    {
        var isTooling = IsToolingOrAnalyzerPath(file.FilePath);
        var isBoundedPythonSubprocess = IsBoundedPythonSubprocessInvocation(repositoryPath, file);
        return CreateCriticalityFinding(
            "TRUST-CODE015",
            isTooling || isBoundedPythonSubprocess ? Severity.Medium : Severity.High,
            isTooling
                ? "Command execution in build or tooling code"
                : isBoundedPythonSubprocess
                    ? "Bounded subprocess execution in critical code"
                    : "Command execution in critical code",
            isTooling
                ? $"{file.FilePath} invokes command execution APIs in build or tooling code."
                : isBoundedPythonSubprocess
                    ? $"{file.FilePath} invokes Python subprocess APIs without shell=True; review argument construction and caller-controlled values."
                : $"{file.FilePath} invokes command execution APIs that can run operating-system commands.",
            "code.command_execution",
            file,
            isTooling
                ? "Review build and tooling command execution for fixed commands, explicit arguments, and untrusted input boundaries."
                : isBoundedPythonSubprocess
                    ? "Keep shell execution disabled, pass arguments as explicit arrays where possible, and validate or allowlist caller-controlled command parts."
                : "Avoid shell execution for untrusted input; use safe APIs, allowlists, and explicit argument boundaries.");
    }

    private static bool IsBoundedPythonSubprocessInvocation(string repositoryPath, CodeCriticalityFile file)
    {
        if (!file.FilePath.EndsWith(".py", StringComparison.OrdinalIgnoreCase) ||
            file.RelevantLines?.TryGetValue(CodeCriticalityReason.CommandExecution, out var lineNumber) != true)
        {
            return false;
        }

        var fullPath = Path.Combine(repositoryPath, file.FilePath.Replace('/', Path.DirectorySeparatorChar));
        if (!RepositoryFileSystem.CanReadAsText(fullPath))
        {
            return false;
        }

        string[] lines;
        try
        {
            lines = File.ReadAllLines(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        var block = ExtractCallBlock(lines, lineNumber - 1);
        if (!block.Contains("subprocess.", StringComparison.Ordinal) ||
            block.Contains("shell=True", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("shell = True", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return block.Contains("subprocess.run(", StringComparison.Ordinal) ||
               block.Contains("subprocess.Popen(", StringComparison.Ordinal) ||
               block.Contains("subprocess.call(", StringComparison.Ordinal) ||
               block.Contains("subprocess.check_call(", StringComparison.Ordinal) ||
               block.Contains("subprocess.check_output(", StringComparison.Ordinal);
    }

    private static string ExtractCallBlock(string[] lines, int startIndex)
    {
        if (startIndex < 0 || startIndex >= lines.Length)
        {
            return string.Empty;
        }

        var selected = new List<string>(capacity: 8);
        var balance = 0;
        for (var index = startIndex; index < lines.Length && index < startIndex + 12; index++)
        {
            var line = lines[index];
            selected.Add(line);
            balance += line.Count(character => character == '(');
            balance -= line.Count(character => character == ')');
            if (selected.Count > 1 && balance <= 0)
            {
                break;
            }
        }

        return string.Join('\n', selected);
    }

    private static int? GetRelevantLine(CodeCriticalityFile file, string evidenceKind)
    {
        var reason = evidenceKind switch
        {
            "code.broad_exception" => CodeCriticalityReason.BroadExceptionHandling,
            "code.deserialization" => CodeCriticalityReason.Deserialization,
            "code.command_execution" => CodeCriticalityReason.CommandExecution,
            "code.dynamic_evaluation" => CodeCriticalityReason.DynamicCodeEvaluation,
            "code.java_serialization_hook" => CodeCriticalityReason.JavaSerializationHook,
            _ => default(CodeCriticalityReason?)
        };

        return reason is not null &&
               file.RelevantLines?.TryGetValue(reason.Value, out var line) == true
            ? line
            : file.FirstRelevantLine;
    }

    private static string FormatReasons(IReadOnlyList<CodeCriticalityReason> reasons) =>
        string.Join(", ", reasons.Select(reason => reason.ToString()));

}
