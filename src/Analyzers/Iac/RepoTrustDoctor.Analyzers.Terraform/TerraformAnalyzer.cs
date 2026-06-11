using System.Text.Json;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

public sealed partial class TerraformAnalyzer : IRepositoryAnalyzer
{
    public string Id => "terraform";

    public string DisplayName => "Terraform Infrastructure Security";

    public AnalysisCategory Category => AnalysisCategory.Infrastructure;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(15);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-TF001", "Terraform allows public ingress from the internet", AnalysisCategory.Infrastructure, Severity.High, Confidence.Medium,
            "A security group rule allows ingress from 0.0.0.0/0 or ::/0.", "Restrict ingress to specific CIDR ranges. Avoid open access unless intentional."),
        new("TRUST-TF002", "Terraform IAM policy uses wildcard action and resource", AnalysisCategory.Infrastructure, Severity.High, Confidence.Medium,
            "An IAM policy grants wildcard actions on wildcard resources.", "Limit IAM policies to specific actions and resources. Avoid '*' for both."),
        new("TRUST-TF003", "Terraform S3 bucket uses public ACL", AnalysisCategory.Infrastructure, Severity.High, Confidence.High,
            "An S3 bucket has a public-read or public-read-write ACL.", "Use private ACL and grant access through bucket policies with least privilege."),
        new("TRUST-TF004", "Terraform S3 bucket encryption may not be configured", AnalysisCategory.Infrastructure, Severity.Medium, Confidence.Low,
            "An S3 bucket does not have visible server-side encryption configuration.", "Enable default S3 server-side encryption or use a separate encryption resource."),
        new("TRUST-TF005", "Terraform provider version constraint is missing", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium,
            "A required_providers entry is missing a version constraint.", "Add version constraints to required_providers entries for reproducible infrastructure."),
        new("TRUST-TF006", "Terraform S3 backend lacks encryption", AnalysisCategory.Infrastructure, Severity.Low, Confidence.Medium,
            "A backend 's3' block does not set encrypt = true.", "Set encrypt = true in the S3 backend configuration."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Process .tf files
        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.tf"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file)) continue;
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

            // Skip lock files and vendor/module dirs
            if (relativePath.Contains(".terraform/", StringComparison.OrdinalIgnoreCase) ||
                relativePath.Contains("/vendor/", StringComparison.OrdinalIgnoreCase) ||
                relativePath.EndsWith(".terraform.lock.hcl", StringComparison.OrdinalIgnoreCase))
                continue;

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            AnalyzeTfContent(content, relativePath, findings);
        }

        // Process .tf.json files
        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.tf.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file)) continue;
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

            if (relativePath.Contains(".terraform/", StringComparison.OrdinalIgnoreCase) ||
                relativePath.Contains("/vendor/", StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken);
                using var doc = JsonDocument.Parse(json);
                AnalyzeTfJson(doc, relativePath, findings);
            }
            catch (JsonException)
            {
                // Skip unparseable JSON
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private void AnalyzeTfContent(string content, string relativePath, List<Finding> findings)
    {
        // Strip comments
        content = CommentStripper.StripComments(content);

        CheckPublicIngress(content, relativePath, findings);
        CheckWildcardIam(content, relativePath, findings);
        CheckPublicAcl(content, relativePath, findings);
        CheckS3Encryption(content, relativePath, findings);
        CheckProviderVersion(content, relativePath, findings);
        CheckBackendEncryption(content, relativePath, findings);
    }

    private void AnalyzeTfJson(JsonDocument doc, string relativePath, List<Finding> findings)
    {
        var root = doc.RootElement;
        if (!root.TryGetProperty("resource", out var resources)) return;

        foreach (var resource in resources.EnumerateObject())
        {
            foreach (var instance in resource.Value.EnumerateObject())
            {
                var type = resource.Name;
                var name = instance.Name;

                // TF001: public ingress via JSON
                if (type is "aws_security_group" or "aws_security_group_rule")
                {
                    if (HasPublicCidrInJson(instance.Value))
                    {
                        findings.Add(CreateFinding("TRUST-TF001", "Public ingress",
                            Severity.High, relativePath, "Security group allows ingress from 0.0.0.0/0 or ::/0.", confidence: Confidence.Medium));
                    }
                }

                // TF003: public ACL via JSON
                if (type is "aws_s3_bucket" or "aws_s3_bucket_acl")
                {
                    if (HasPublicAclInJson(instance.Value))
                    {
                        findings.Add(CreateFinding("TRUST-TF003", "Public S3 ACL",
                            Severity.High, relativePath, "S3 bucket has public-read or public-read-write ACL."));
                    }
                }
            }
        }
    }

    // ── TF001: public ingress ─────────────────────────────────────────

    private void CheckPublicIngress(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match block in SecurityGroupBlockPattern().Matches(content))
        {
            var blockText = block.Value;
            var isIngress = blockText.Contains("ingress", StringComparison.OrdinalIgnoreCase);
            var isEgressOnly = blockText.Contains("egress", StringComparison.OrdinalIgnoreCase) && !isIngress;
            var hasPublicCidr = blockText.Contains("0.0.0.0/0", StringComparison.Ordinal) ||
                                blockText.Contains("::/0", StringComparison.Ordinal);

            if (isIngress && !isEgressOnly && hasPublicCidr)
            {
                findings.Add(CreateFinding("TRUST-TF001", "Public ingress from internet",
                    Severity.High, relativePath,
                    "Security group rule allows ingress from 0.0.0.0/0 or ::/0.",
                    confidence: Confidence.Medium));
            }
        }
    }

    // ── TF002: wildcard IAM ───────────────────────────────────────────

    private void CheckWildcardIam(string content, string relativePath, List<Finding> findings)
    {
        var hasActionStar = IamActionStarPattern().IsMatch(content);
        var hasResourceStar = IamResourceStarPattern().IsMatch(content);

        if (hasActionStar && hasResourceStar)
        {
            findings.Add(CreateFinding("TRUST-TF002", "Wildcard IAM policy",
                Severity.High, relativePath,
                "IAM policy grants wildcard actions on wildcard resources.",
                confidence: Confidence.Medium));
        }
    }

    // ── TF003: S3 public ACL ──────────────────────────────────────────

    private void CheckPublicAcl(string content, string relativePath, List<Finding> findings)
    {
        if (PublicAclPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-TF003", "S3 bucket public ACL",
                Severity.High, relativePath, "S3 bucket has public-read or public-read-write ACL."));
        }
    }

    // ── TF004: S3 encryption ──────────────────────────────────────────

    private void CheckS3Encryption(string content, string relativePath, List<Finding> findings)
    {
        if (!S3BucketPattern().IsMatch(content)) return;

        // Check if encryption block exists in same file
        if (S3EncryptionPattern().IsMatch(content)) return;

        findings.Add(CreateFinding("TRUST-TF004", "S3 encryption not visible",
            Severity.Medium, relativePath,
            "S3 bucket found but no server_side_encryption_configuration block visible in this file.",
            confidence: Confidence.Low));
    }

    // ── TF005: provider version ───────────────────────────────────────

    private void CheckProviderVersion(string content, string relativePath, List<Finding> findings)
    {
        if (!content.Contains("required_providers", StringComparison.OrdinalIgnoreCase))
            return;

        // For each source = "..." line, check if a version line exists in nearby context
        foreach (Match match in ProviderSourcePattern().Matches(content))
        {
            var source = match.Groups["source"].Value;
            var matchEnd = match.Index + match.Length;

            // Look ahead up to 200 chars for a version line
            var ahead = matchEnd + 200 < content.Length ? 200 : content.Length - matchEnd;
            var following = content.Substring(matchEnd, ahead);

            if (!following.Contains("version", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(CreateFinding("TRUST-TF005", "Provider missing version constraint",
                    Severity.Medium, relativePath,
                    $"Provider '{source}' has no version constraint.",
                    GetLineNumber(content, match.Index),
                    confidence: Confidence.Medium));
            }
        }
    }

    // ── TF006: backend encryption ─────────────────────────────────────

    private void CheckBackendEncryption(string content, string relativePath, List<Finding> findings)
    {
        if (!S3BackendPattern().IsMatch(content)) return;
        if (content.Contains("encrypt = true", StringComparison.OrdinalIgnoreCase))
            return;

        findings.Add(CreateFinding("TRUST-TF006", "S3 backend missing encryption",
            Severity.Low, relativePath,
            "backend \"s3\" block does not set encrypt = true.",
            confidence: Confidence.Medium));
    }

    // ── JSON helpers ──────────────────────────────────────────────────

    private static bool HasPublicCidrInJson(JsonElement element)
    {
        if (!element.TryGetProperty("type", out var type) || type.GetString() != "ingress") return false;
        if (element.TryGetProperty("cidr_blocks", out var cidrs))
        {
            foreach (var c in cidrs.EnumerateArray())
                if (c.GetString() is "0.0.0.0/0" or "::/0") return true;
        }
        return false;
    }

    private static bool HasPublicAclInJson(JsonElement element)
    {
        if (element.TryGetProperty("acl", out var acl))
        {
            var v = acl.GetString();
            return v is "public-read" or "public-read-write";
        }
        return false;
    }

    // ── Common helpers ────────────────────────────────────────────────

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.Infrastructure, severity, confidence, title,
            [new Evidence("terraform", evidence, filePath, lineNumber)],
            new Recommendation("Review the Terraform configuration and apply the recommended fix."));
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    // ── Patterns ──────────────────────────────────────────────────────

    [GeneratedRegex(@"(?s)(?:ingress|egress)\s*\{[\s\S]*?\}")]
    private static partial Regex SecurityGroupBlockPattern();

    [GeneratedRegex(@"""?\b[Aa]ctions?\b""?\s*(?:=|:)\s*(?:\[\s*)?""\*""")]
    private static partial Regex IamActionStarPattern();

    [GeneratedRegex(@"""?\b[Rr]esources?\b""?\s*(?:=|:)\s*(?:\[\s*)?""\*""")]
    private static partial Regex IamResourceStarPattern();

    [GeneratedRegex(@"acl\s*=\s*""public-read(?:-write)?""", RegexOptions.IgnoreCase)]
    private static partial Regex PublicAclPattern();

    [GeneratedRegex(@"resource\s+""aws_s3_bucket""", RegexOptions.IgnoreCase)]
    private static partial Regex S3BucketPattern();

    [GeneratedRegex(@"server_side_encryption_configuration", RegexOptions.IgnoreCase)]
    private static partial Regex S3EncryptionPattern();

    [GeneratedRegex(@"(?m)^\s*source\s*=\s*""(?<source>[^""]+)""\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ProviderSourcePattern();

    [GeneratedRegex(@"backend\s+""s3""", RegexOptions.IgnoreCase)]
    private static partial Regex S3BackendPattern();
}

/// <summary>
/// Minimal comment stripper for Terraform HCL files. Removes #, //, and /* */ comments.
/// Does not handle heredoc strings fully; conservative enough for these rules.
/// </summary>
internal static class CommentStripper
{
    public static string StripComments(string content)
    {
        var result = new System.Text.StringBuilder(content.Length);
        var i = 0;
        while (i < content.Length)
        {
            // Block comments /* ... */
            if (i + 1 < content.Length && content[i] == '/' && content[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < content.Length && !(content[i] == '*' && content[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }

            // Line comments # or //
            if (content[i] == '#' || (i + 1 < content.Length && content[i] == '/' && content[i + 1] == '/'))
            {
                while (i < content.Length && content[i] != '\n')
                    i++;
                if (i < content.Length) result.Append('\n');
                i++;
                continue;
            }

            result.Append(content[i]);
            i++;
        }
        return result.ToString();
    }
}
