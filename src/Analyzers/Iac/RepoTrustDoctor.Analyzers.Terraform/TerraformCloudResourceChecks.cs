using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

/// <summary>
/// Cloud resource checks for Terraform.
/// Produces TRUST-TF009 (publicly accessible DB), TRUST-TF010 (KMS key rotation disabled),
/// and TRUST-TF011 (S3 public-access block explicitly disabled).
/// </summary>
internal static partial class TerraformCloudResourceChecks
{
    public static void CheckAll(IReadOnlyList<TerraformBlock> blocks, string relativePath, List<Finding> findings)
    {
        foreach (var block in blocks)
        {
            var header = block.Header;
            var text = block.Text;

            if (header.Contains("aws_db_instance", StringComparison.OrdinalIgnoreCase) ||
                header.Contains("aws_rds_cluster", StringComparison.OrdinalIgnoreCase))
            {
                CheckPublicDatabase(text, block, relativePath, findings);
            }
            else if (header.Contains("aws_kms_key", StringComparison.OrdinalIgnoreCase))
            {
                CheckKmsKeyRotation(text, block, relativePath, findings);
            }
            else if (header.Contains("aws_s3_bucket_public_access_block", StringComparison.OrdinalIgnoreCase))
            {
                CheckS3PublicAccessBlock(text, block, relativePath, findings);
            }
        }
    }

    // ── TRUST-TF009: Publicly accessible database ────────────────────

    private static void CheckPublicDatabase(string text, TerraformBlock block, string relativePath, List<Finding> findings)
    {
        var match = PubliclyAccessiblePattern().Match(text);
        if (!match.Success)
        {
            return;
        }

        var value = match.Groups["value"].Value.Trim();
        // Only flag literal "true". Skip variables and locals.
        if (!IsLiteralBoolean(value, expected: true))
        {
            return;
        }

        var resourceType = ExtractResourceType(block.Header);
        var resourceName = block.Labels.ElementAtOrDefault(1) ?? "<unnamed>";
        var identityKey = $"tf009|{relativePath}|{resourceType}|{resourceName}";

        findings.Add(new Finding(
            "TRUST-TF009",
            "Database resource is publicly accessible",
            AnalysisCategory.Infrastructure,
            Severity.High,
            Confidence.High,
            $"{resourceType} '{resourceName}' has publicly_accessible = true.",
            [new Evidence("terraform-database", $"{resourceType} '{resourceName}' is publicly accessible.", relativePath, block.StartLine)],
            new Recommendation("Set publicly_accessible = false for database resources unless public access is explicitly required."),
            IdentityKey: identityKey));
    }

    // ── TRUST-TF010: KMS key rotation explicitly disabled ────────────

    private static void CheckKmsKeyRotation(string text, TerraformBlock block, string relativePath, List<Finding> findings)
    {
        var match = EnableKeyRotationPattern().Match(text);
        if (!match.Success)
        {
            return; // Not explicitly configured — don't report.
        }

        var value = match.Groups["value"].Value.Trim();
        if (!IsLiteralBoolean(value, expected: false))
        {
            return;
        }

        var resourceName = block.Labels.ElementAtOrDefault(1) ?? "<unnamed>";
        var identityKey = $"tf010|{relativePath}|aws_kms_key|{resourceName}";

        findings.Add(new Finding(
            "TRUST-TF010",
            "KMS key rotation is explicitly disabled",
            AnalysisCategory.Infrastructure,
            Severity.Medium,
            Confidence.High,
            $"aws_kms_key '{resourceName}' has enable_key_rotation = false.",
            [new Evidence("terraform-kms", $"KMS key rotation is explicitly disabled for '{resourceName}'.", relativePath, block.StartLine)],
            new Recommendation("Set enable_key_rotation = true for KMS keys to enable automatic annual key rotation."),
            IdentityKey: identityKey));
    }

    // ── TRUST-TF011: S3 public-access block explicitly disabled ──────

    private static readonly string[] S3PublicAccessFlags =
    [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets"
    ];

    private static void CheckS3PublicAccessBlock(string text, TerraformBlock block, string relativePath, List<Finding> findings)
    {
        var disabledFlags = new List<string>();

        foreach (var flag in S3PublicAccessFlags)
        {
            var match = Regex.Match(text, $@"(?m)^\s*{Regex.Escape(flag)}\s*=\s*(?<value>\S+)", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var value = match.Groups["value"].Value.Trim().Trim('"');
            if (IsLiteralBoolean(value, expected: false))
            {
                disabledFlags.Add(flag);
            }
        }

        if (disabledFlags.Count == 0)
        {
            return;
        }

        var resourceName = block.Labels.ElementAtOrDefault(1) ?? "<unnamed>";
        var identityKey = $"tf011|{relativePath}|aws_s3_bucket_public_access_block|{resourceName}";
        var disabledList = string.Join(", ", disabledFlags);

        findings.Add(new Finding(
            "TRUST-TF011",
            "S3 public-access block is explicitly disabled",
            AnalysisCategory.Infrastructure,
            Severity.High,
            Confidence.High,
            $"aws_s3_bucket_public_access_block '{resourceName}' disables public-access protections: {disabledList}.",
            [new Evidence("terraform-s3-pab", $"S3 public-access block protections disabled: {disabledList}.", relativePath, block.StartLine)],
            new Recommendation($"Set {disabledList} = true to protect the S3 bucket from public access."),
            IdentityKey: identityKey));
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string ExtractResourceType(string header)
    {
        var match = ResourceTypePattern().Match(header);
        return match.Success ? match.Groups["type"].Value : header;
    }

    /// <summary>
    /// Returns true when the value is a literal boolean equal to the expected value.
    /// Rejects variable references ($var.x), local references (local.x), and unknown values.
    /// </summary>
    private static bool IsLiteralBoolean(string value, bool expected)
    {
        var normalized = value.Trim().Trim('"', '\'');
        if (normalized.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return expected;
        }
        if (normalized.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            return !expected;
        }
        // Variable or local reference — no high-confidence finding.
        return false;
    }

    // ── Regexes ──────────────────────────────────────────────────────

    [GeneratedRegex(@"(?m)^\s*publicly_accessible\s*=\s*(?<value>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex PubliclyAccessiblePattern();

    [GeneratedRegex(@"(?m)^\s*enable_key_rotation\s*=\s*(?<value>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex EnableKeyRotationPattern();

    [GeneratedRegex(@"resource\s+""(?<type>\S+)""", RegexOptions.IgnoreCase)]
    private static partial Regex ResourceTypePattern();
}
