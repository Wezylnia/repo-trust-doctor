using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Docker;

/// <summary>
/// Docker supply-chain hardening checks.
/// Produces TRUST-DOCKER013, TRUST-DOCKER015, and TRUST-DOCKER016 findings.
/// Every repeatable finding includes a stable identity key.
/// </summary>
internal static partial class DockerSupplyChainChecks
{
    public static void CheckAll(string content, string relativePath, DockerBasicAnalyzer.DockerfileStage[] stages, List<Finding> findings)
    {
        var stageAliases = new HashSet<string>(StringComparer.Ordinal);
        var stageCount = stages.Length;
        for (var index = 0; index < stages.Length; index++)
        {
            var alias = ExtractStageAlias(stages[index].Content);
            if (alias is not null)
            {
                stageAliases.Add(alias);
            }
        }

        CheckExternalCopyFromDigest(content, relativePath, stageAliases, stageCount, findings);

        var effectiveStages = stages.Length == 0
            ? [new DockerBasicAnalyzer.DockerfileStage(string.Empty, content)]
            : stages;
        for (var stageIndex = 0; stageIndex < effectiveStages.Length; stageIndex++)
        {
            CheckPackageCacheCleanup(
                effectiveStages[stageIndex].Content,
                relativePath,
                stageIndex,
                findings);
        }

        CheckSecretLikeArgs(content, relativePath, findings);
    }

    // ── TRUST-DOCKER013: External COPY --from not digest-pinned ──────

    private static void CheckExternalCopyFromDigest(
        string content,
        string relativePath,
        HashSet<string> stageAliases,
        int stageCount,
        List<Finding> findings)
    {
        var occurrences = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (Match copyMatch in CopyInstructionPattern().Matches(content))
        {
            var options = copyMatch.Groups["options"].Value;
            var fromMatch = CopyFromOptionPattern().Match(options);
            if (!fromMatch.Success)
            {
                continue;
            }

            var fromRef = fromMatch.Groups["fromRef"].Value.Trim();
            var operands = NormalizeForIdentity(copyMatch.Groups["operands"].Value);

            if (stageAliases.Contains(fromRef))
            {
                continue;
            }

            if (int.TryParse(fromRef, out var referencedStage) &&
                referencedStage >= 0 && referencedStage < stageCount)
            {
                continue;
            }

            if (fromRef.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var occurrenceKey = $"{fromRef}|{operands}";
            var occurrence = occurrences.GetValueOrDefault(occurrenceKey);
            occurrences[occurrenceKey] = occurrence + 1;

            var lineNumber = GetLineNumber(content, copyMatch.Index);
            var identityKey = $"docker013|{relativePath}|{fromRef}|{operands}|{occurrence}";

            findings.Add(new Finding(
                "TRUST-DOCKER013",
                "External build stage is not digest-pinned",
                AnalysisCategory.Containers,
                Severity.Medium,
                Confidence.High,
                $"COPY --from={fromRef} references an external image without a digest pin.",
                [new Evidence(
                    "dockerfile",
                    $"COPY --from={fromRef} is not pinned to an immutable digest.",
                    relativePath,
                    lineNumber,
                    copyMatch.Value.Trim())],
                new Recommendation("Pin external COPY --from images with a digest reference (e.g. image@sha256:...)."),
                IdentityKey: identityKey));
        }
    }

    // ── TRUST-DOCKER015: Package-manager cache left in layer ─────────

    private static void CheckPackageCacheCleanup(
        string content,
        string relativePath,
        int stageIndex,
        List<Finding> findings)
    {
        var occurrences = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in RunInstructionPattern().Matches(content))
        {
            var runLine = match.Value;
            var lineNumber = GetLineNumber(content, match.Index);

            if (AptGetInstallPattern().IsMatch(runLine))
            {
                if (!AptGetCleanupPattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding(relativePath, lineNumber, stageIndex, "apt-get", occurrences, findings);
                }
                continue;
            }

            if (ApkAddPattern().IsMatch(runLine))
            {
                if (!ApkNoCachePattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding(relativePath, lineNumber, stageIndex, "apk", occurrences, findings);
                }
                continue;
            }

            if (YumInstallPattern().IsMatch(runLine))
            {
                if (!YumCleanAllPattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding(relativePath, lineNumber, stageIndex, "yum", occurrences, findings);
                }
                continue;
            }

            if (DnfInstallPattern().IsMatch(runLine) &&
                !DnfCleanAllPattern().IsMatch(runLine))
            {
                AddPackageCacheFinding(relativePath, lineNumber, stageIndex, "dnf", occurrences, findings);
            }
        }
    }

    private static void AddPackageCacheFinding(
        string relativePath,
        int lineNumber,
        int stageIndex,
        string packageManager,
        IDictionary<string, int> occurrences,
        List<Finding> findings)
    {
        var occurrence = occurrences.GetValueOrDefault(packageManager);
        occurrences[packageManager] = occurrence + 1;
        var identityKey = $"docker015|{relativePath}|stage:{stageIndex}|{packageManager}|{occurrence}";

        findings.Add(new Finding(
            "TRUST-DOCKER015",
            "Package-manager cache remains in the image layer",
            AnalysisCategory.Containers,
            Severity.Low,
            Confidence.Medium,
            $"RUN instruction uses {packageManager} to install packages without cleaning the cache in the same layer.",
            [new Evidence("dockerfile", $"Package manager cache ({packageManager}) is not cleaned in this RUN layer.", relativePath, lineNumber)],
            new Recommendation($"Combine {packageManager} install with cache cleanup (e.g. rm -rf /var/lib/apt/lists/*, apk --no-cache, yum clean all, dnf clean all) in the same RUN instruction."),
            IdentityKey: identityKey));
    }

    // ── TRUST-DOCKER016: Secret-like ARG ─────────────────────────────

    private static readonly HashSet<string> SafeArgNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "VERSION", "BUILD_CONFIGURATION", "TARGETARCH", "TARGETOS",
        "TARGETPLATFORM", "BUILDPLATFORM", "TARGETVARIANT",
        "BUILD_VERSION", "CONFIGURATION", "NODE_VERSION", "DOTNET_VERSION",
        "GO_VERSION", "RUST_VERSION", "PYTHON_VERSION",
    };

    private static readonly HashSet<string> SecretLikeArgNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "TOKEN", "AUTH_TOKEN", "API_TOKEN",
        "PASSWORD", "DB_PASSWORD", "CERTIFICATE_PASSWORD",
        "SECRET", "CLIENT_SECRET",
        "API_KEY", "ACCESS_KEY", "SECRET_KEY",
        "PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY",
        "CREDENTIALS",
    };

    private static readonly HashSet<string> SecretSuffixTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "TOKEN", "PASSWORD", "PASS", "SECRET", "KEY", "CREDENTIALS", "CERTIFICATE",
    };

    private static void CheckSecretLikeArgs(string content, string relativePath, List<Finding> findings)
    {
        var occurrences = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in ArgInstructionPattern().Matches(content))
        {
            var argName = match.Groups["name"].Value.Trim();

            if (SafeArgNames.Contains(argName) || !IsSecretLikeArg(argName))
            {
                continue;
            }

            var occurrence = occurrences.GetValueOrDefault(argName);
            occurrences[argName] = occurrence + 1;
            var lineNumber = GetLineNumber(content, match.Index);
            var identityKey = $"docker016|{relativePath}|{argName}|{occurrence}";

            findings.Add(new Finding(
                "TRUST-DOCKER016",
                "Secret-like build argument uses ordinary ARG",
                AnalysisCategory.Containers,
                Severity.Medium,
                Confidence.High,
                $"ARG {argName} appears secret-like. Ordinary build arguments are persisted in the image history.",
                [new Evidence("dockerfile", $"ARG {argName} is a secret-like build argument.", relativePath, lineNumber, match.Value.Trim())],
                new Recommendation("Use BuildKit secret mounts (RUN --mount=type=secret,id=...) instead of ordinary build arguments for secrets."),
                IdentityKey: identityKey));
        }
    }

    private static bool IsSecretLikeArg(string argName)
    {
        if (SecretLikeArgNames.Contains(argName))
        {
            return true;
        }

        var tokens = argName.Split('_', StringSplitOptions.RemoveEmptyEntries);
        return tokens.Length > 0 && SecretSuffixTokens.Contains(tokens[^1]);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string? ExtractStageAlias(string stageContent)
    {
        var match = FromAliasPattern().Match(stageContent);
        return match.Success ? match.Groups["alias"].Value.Trim() : null;
    }

    private static string NormalizeForIdentity(string value) =>
        WhitespacePattern().Replace(value.Trim(), " ");

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

    // ── Regexes ──────────────────────────────────────────────────────

    [GeneratedRegex(@"(?mi)^\s*COPY\b(?<options>(?:\s+--[^\s]+)*)\s+(?<operands>.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex CopyInstructionPattern();

    [GeneratedRegex(@"(?:^|\s)--from=(?<fromRef>[^\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex CopyFromOptionPattern();

    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+\s+AS\s+(?<alias>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex FromAliasPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.+$")]
    private static partial Regex RunInstructionPattern();

    [GeneratedRegex(@"\bapt-get\s+install\b", RegexOptions.IgnoreCase)]
    private static partial Regex AptGetInstallPattern();

    [GeneratedRegex(@"rm\s+-rf\s+/var/lib/apt/lists/\*", RegexOptions.IgnoreCase)]
    private static partial Regex AptGetCleanupPattern();

    [GeneratedRegex(@"\bapk\s+add\b", RegexOptions.IgnoreCase)]
    private static partial Regex ApkAddPattern();

    [GeneratedRegex(@"--no-cache", RegexOptions.IgnoreCase)]
    private static partial Regex ApkNoCachePattern();

    [GeneratedRegex(@"\byum\s+install\b", RegexOptions.IgnoreCase)]
    private static partial Regex YumInstallPattern();

    [GeneratedRegex(@"yum\s+clean\s+all", RegexOptions.IgnoreCase)]
    private static partial Regex YumCleanAllPattern();

    [GeneratedRegex(@"\bdnf\s+install\b", RegexOptions.IgnoreCase)]
    private static partial Regex DnfInstallPattern();

    [GeneratedRegex(@"dnf\s+clean\s+all", RegexOptions.IgnoreCase)]
    private static partial Regex DnfCleanAllPattern();

    [GeneratedRegex(@"(?mi)^\s*ARG\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex ArgInstructionPattern();

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespacePattern();
}
