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
        // Collect stage aliases for resolving COPY --from references.
        var stageAliases = new HashSet<string>(StringComparer.Ordinal);
        var stageCount = stages.Length;
        for (var i = 0; i < stages.Length; i++)
        {
            var alias = ExtractStageAlias(stages[i].Content);
            if (alias is not null)
            {
                stageAliases.Add(alias);
            }
        }

        // TRUST-DOCKER013: Scan once per Dockerfile, not per stage.
        CheckExternalCopyFromDigest(content, relativePath, stageAliases, stageCount, findings);

        foreach (var stage in stages.Length == 0
                     ? [new DockerBasicAnalyzer.DockerfileStage(string.Empty, content)]
                     : stages)
        {
            CheckPackageCacheCleanup(stage.Content, relativePath, findings);
        }

        CheckSecretLikeArgs(content, relativePath, findings);
    }

    // ── TRUST-DOCKER013: External COPY --from not digest-pinned ──────

    private static void CheckExternalCopyFromDigest(
        string content, string relativePath, HashSet<string> stageAliases, int stageCount, List<Finding> findings)
    {
        foreach (Match match in CopyFromPattern().Matches(content))
        {
            var fromRef = match.Groups["fromRef"].Value.Trim();
            var rawLine = match.Value;

            // Skip if referencing a stage alias declared in the same Dockerfile.
            if (stageAliases.Contains(fromRef))
            {
                continue;
            }

            // Skip numeric stage references: --from=0, --from=1, etc.
            if (int.TryParse(fromRef, out var stageIndex) &&
                stageIndex >= 0 && stageIndex < stageCount)
            {
                continue;
            }

            // Skip if already pinned by digest.
            if (fromRef.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var lineNumber = GetLineNumber(content, match.Index);
            var identityKey = $"docker013|{relativePath}|{lineNumber}|{fromRef}";

            findings.Add(new Finding(
                "TRUST-DOCKER013",
                "External build stage is not digest-pinned",
                AnalysisCategory.Containers,
                Severity.Medium,
                Confidence.High,
                $"COPY --from={fromRef} references an external image without a digest pin.",
                [new Evidence("dockerfile", $"COPY --from={fromRef} is not pinned to an immutable digest.", relativePath, lineNumber, rawLine.Trim())],
                new Recommendation("Pin external COPY --from images with a digest reference (e.g. image@sha256:...)."),
                IdentityKey: identityKey));
        }
    }

    // ── TRUST-DOCKER015: Package-manager cache left in layer ─────────

    private static void CheckPackageCacheCleanup(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in RunInstructionPattern().Matches(content))
        {
            var runLine = match.Value;
            var lineNumber = GetLineNumber(content, match.Index);

            // apt-get
            if (AptGetInstallPattern().IsMatch(runLine))
            {
                if (!AptGetCleanupPattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding("TRUST-DOCKER015", relativePath, lineNumber, "apt-get", findings);
                }
                continue;
            }

            // apk
            if (ApkAddPattern().IsMatch(runLine))
            {
                if (!ApkNoCachePattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding("TRUST-DOCKER015", relativePath, lineNumber, "apk", findings);
                }
                continue;
            }

            // yum
            if (YumInstallPattern().IsMatch(runLine))
            {
                if (!YumCleanAllPattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding("TRUST-DOCKER015", relativePath, lineNumber, "yum", findings);
                }
                continue;
            }

            // dnf
            if (DnfInstallPattern().IsMatch(runLine))
            {
                if (!DnfCleanAllPattern().IsMatch(runLine))
                {
                    AddPackageCacheFinding("TRUST-DOCKER015", relativePath, lineNumber, "dnf", findings);
                }
            }
        }
    }

    private static void AddPackageCacheFinding(
        string ruleId, string relativePath, int lineNumber, string packageManager, List<Finding> findings)
    {
        var identityKey = $"docker015|{relativePath}|{lineNumber}|{packageManager}";

        findings.Add(new Finding(
            ruleId,
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

    // Suffixes that indicate a secret when the token right before it is a secret indicator.
    private static readonly HashSet<string> SecretSuffixTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "TOKEN", "PASSWORD", "PASS", "SECRET", "KEY", "CREDENTIALS", "CERTIFICATE",
    };

    private static void CheckSecretLikeArgs(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in ArgInstructionPattern().Matches(content))
        {
            var argName = match.Groups["name"].Value.Trim();

            // Skip safe arguments.
            if (SafeArgNames.Contains(argName))
            {
                continue;
            }

            // Check if this looks like a secret using token-aware matching.
            if (!IsSecretLikeArg(argName))
            {
                continue;
            }

            var lineNumber = GetLineNumber(content, match.Index);
            var identityKey = $"docker016|{relativePath}|{lineNumber}|{argName}";

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
        // Direct match against known secret patterns (exact or prefix).
        if (SecretLikeArgNames.Contains(argName))
            return true;

        // Token-aware suffix matching: split on underscores, check if the last
        // meaningful token is a secret indicator.
        // e.g. SIGNING_CREDENTIALS -> "CREDENTIALS" is secret suffix
        // e.g. PRIVATE_REGISTRY -> "REGISTRY" is NOT a secret suffix
        // e.g. SIGNING_ALGORITHM -> "ALGORITHM" is NOT a secret suffix
        // e.g. CERTIFICATE_PATH -> "PATH" is NOT a secret suffix
        // e.g. CERTIFICATE_FILE -> "FILE" is NOT a secret suffix
        var tokens = argName.Split('_', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length > 0)
        {
            var lastToken = tokens[^1];
            if (SecretSuffixTokens.Contains(lastToken))
            {
                return true;
            }
        }

        return false;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string? ExtractStageAlias(string stageContent)
    {
        var match = FromAliasPattern().Match(stageContent);
        return match.Success ? match.Groups["alias"].Value.Trim() : null;
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

    // ── Regexes ──────────────────────────────────────────────────────

    // COPY --from=<image> (external image reference)
    [GeneratedRegex(@"(?mi)^\s*COPY\s+--from=(?<fromRef>[^\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex CopyFromPattern();

    // FROM <image> AS <alias>
    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+\s+AS\s+(?<alias>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex FromAliasPattern();

    // Package manager patterns
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

    // ARG <name>
    [GeneratedRegex(@"(?mi)^\s*ARG\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex ArgInstructionPattern();

    // RUN --mount=type=secret,id=<id>
    [GeneratedRegex(@"--mount=type=secret[^ ]*id=(?<id>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SecretMountPattern();
}
