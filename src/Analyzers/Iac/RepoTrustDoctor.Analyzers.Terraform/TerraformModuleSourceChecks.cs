using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

/// <summary>
/// TRUST-TF008: Remote Terraform module source is mutable.
/// Detects Git module sources (git::https://...) that reference a mutable ref
/// (branch name, tag) instead of an immutable full commit SHA.
/// </summary>
internal static partial class TerraformModuleSourceChecks
{
    public static void CheckAll(IReadOnlyList<TerraformBlock> blocks, string relativePath, List<Finding> findings)
    {
        foreach (var block in blocks)
        {
            if (!IsModuleBlock(block))
            {
                continue;
            }

            var source = ExtractSource(block.Text);
            if (source is null)
            {
                continue;
            }

            // Only flag remote Git sources.
            if (!source.StartsWith("git::", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Skip local paths: git::./module or git::../shared (these are relative).
            var afterGit = source["git::".Length..].Trim();
            if (afterGit.StartsWith('.') || afterGit.StartsWith('/'))
            {
                continue;
            }

            // Extract ref parameter.
            var refMatch = GitRefPattern().Match(source);
            if (!refMatch.Success)
            {
                // No ref at all — mutable (default branch).
                AddFinding(relativePath, block, source, findings);
                continue;
            }

            var refValue = refMatch.Groups["ref"].Value.Trim();
            if (IsCommitSha(refValue))
            {
                continue; // PASS: full commit SHA
            }

            // Branch name, tag, or short SHA — mutable.
            AddFinding(relativePath, block, source, findings);
        }
    }

    private static void AddFinding(string relativePath, TerraformBlock block, string source, List<Finding> findings)
    {
        var moduleName = block.Labels.ElementAtOrDefault(0) ?? "<unnamed>";
        var identityKey = $"tf008|{relativePath}|module|{moduleName}|{source}";

        findings.Add(new Finding(
            "TRUST-TF008",
            "Remote Terraform module source is mutable",
            AnalysisCategory.Dependencies,
            Severity.Medium,
            Confidence.High,
            $"Module '{moduleName}' references a Git source '{source}' without an immutable commit SHA ref.",
            [new Evidence("terraform-module-source", $"Module source '{source}' is not pinned to a full commit SHA.", relativePath, block.StartLine)],
            new Recommendation("Pin Git module sources to a full commit SHA (40 hex characters), e.g. ?ref=abc123..."),
            IdentityKey: identityKey));
    }

    private static bool IsModuleBlock(TerraformBlock block) =>
        block.Header.StartsWith("module", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractSource(string blockText)
    {
        var match = ModuleSourcePattern().Match(blockText);
        return match.Success ? match.Groups["source"].Value.Trim().Trim('"') : null;
    }

    private static bool IsCommitSha(string value) =>
        value.Length == 40 && value.All(c => char.IsAsciiHexDigit(c));

    // source = "..." (extract the value between quotes)
    [GeneratedRegex(@"(?m)^\s*source\s*=\s*""(?<source>[^""]+)""", RegexOptions.IgnoreCase)]
    private static partial Regex ModuleSourcePattern();

    // Extract ref parameter from Git source URL
    // e.g. git::https://example/repo.git?ref=main
    [GeneratedRegex(@"[?&]ref=(?<ref>[^&\s""]+)", RegexOptions.IgnoreCase)]
    private static partial Regex GitRefPattern();
}
