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
        new("TRUST-TF007", "Terraform dependency lockfile is missing", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High,
            "No .terraform.lock.hcl exists alongside .tf files that declare required_providers.", "Run 'terraform providers lock' to create a .terraform.lock.hcl for reproducible provider versions."),
        new("TRUST-TF008", "Remote Terraform module source is mutable", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High,
            "A module references a remote Git source without an immutable commit SHA ref.", "Pin Git module sources to a full commit SHA, e.g. ?ref=abc123..."),
        new("TRUST-TF009", "Database resource is publicly accessible", AnalysisCategory.Infrastructure, Severity.High, Confidence.High,
            "A database resource has publicly_accessible = true.", "Set publicly_accessible = false unless public access is explicitly required."),
        new("TRUST-TF010", "KMS key rotation is explicitly disabled", AnalysisCategory.Infrastructure, Severity.Medium, Confidence.High,
            "A KMS key has enable_key_rotation = false.", "Set enable_key_rotation = true to enable automatic annual key rotation."),
        new("TRUST-TF011", "S3 public-access block is explicitly disabled", AnalysisCategory.Infrastructure, Severity.High, Confidence.High,
            "An S3 public-access block resource disables one or more public-access protections.", "Set all public-access block flags to true to protect the bucket."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var lockfileDirectoriesChecked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Process .tf files
        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.tf"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file)) continue;
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

            if (ShouldSkipTerraformFile(relativePath))
                continue;

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            AnalyzeTfContent(content, relativePath, findings);

            // WP4: Lockfile check per directory (only once per directory).
            var dir = Path.GetDirectoryName(relativePath)?.Replace('\\', '/') ?? ".";
            if (lockfileDirectoriesChecked.Add(dir))
            {
                TerraformLockfileChecks.CheckAll(context.RepositoryPath, dir, content, findings);
            }
        }

        // Process .tf.json files
        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.tf.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file)) continue;
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

            if (ShouldSkipTerraformFile(relativePath))
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
        var blocks = TerraformBlockExtractor.Extract(content);

        CheckPublicIngress(content, relativePath, findings);
        CheckWildcardIam(content, blocks, relativePath, findings);
        CheckPublicAcl(content, relativePath, findings);
        CheckS3Encryption(content, blocks, relativePath, findings);
        CheckProviderVersion(content, blocks, relativePath, findings);
        CheckBackendEncryption(blocks, relativePath, findings);

        // WP4: New supply-chain and cloud resource checks.
        TerraformModuleSourceChecks.CheckAll(blocks, relativePath, findings);
        TerraformCloudResourceChecks.CheckAll(blocks, relativePath, findings);
    }

    private void AnalyzeTfJson(JsonDocument doc, string relativePath, List<Finding> findings)
    {
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("resource", out var resources) ||
            resources.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var resource in resources.EnumerateObject())
        {
            if (resource.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var instance in resource.Value.EnumerateObject())
            {
                if (instance.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var type = resource.Name;
                var name = instance.Name;

                // TF001: public ingress via JSON
                if (type is "aws_security_group" or "aws_security_group_rule")
                {
                    if (HasPublicCidrInJson(type, instance.Value))
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

    private void CheckWildcardIam(
        string content,
        IReadOnlyList<TerraformBlock> blocks,
        string relativePath,
        List<Finding> findings)
    {
        foreach (var block in blocks.Where(IsIamPolicyBlock))
        {
            if (!ContainsWildcardActionAndResourceInSameStatement(block.Text))
            {
                continue;
            }

            findings.Add(CreateFinding(
                "TRUST-TF002",
                "Wildcard IAM policy",
                Severity.High,
                relativePath,
                "IAM policy grants wildcard actions on wildcard resources.",
                block.StartLine,
                Confidence.Medium));
        }
    }

    private static bool IsIamPolicyBlock(TerraformBlock block) =>
        block.Header.Contains("aws_iam_policy", StringComparison.OrdinalIgnoreCase) ||
        block.Header.Contains("aws_iam_role_policy", StringComparison.OrdinalIgnoreCase) ||
        block.Header.Contains("aws_iam_policy_document", StringComparison.OrdinalIgnoreCase) ||
        block.Text.Contains("Statement", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsWildcardActionAndResourceInSameStatement(string text)
    {
        var statementIndex = text.IndexOf("Statement", StringComparison.OrdinalIgnoreCase);
        if (statementIndex < 0)
        {
            return HasWildcardActionAndResource(text);
        }

        var statementText = text[statementIndex..];
        var chunks = TerraformBlockExtractor.ExtractBraceChunks(statementText);
        return chunks.Count == 0
            ? HasWildcardActionAndResource(statementText)
            : chunks.Any(HasWildcardActionAndResource);
    }

    private static bool HasWildcardActionAndResource(string text) =>
        IamActionStarPattern().IsMatch(text) &&
        IamResourceStarPattern().IsMatch(text);

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

    private void CheckS3Encryption(
        string content,
        IReadOnlyList<TerraformBlock> blocks,
        string relativePath,
        List<Finding> findings)
    {
        var buckets = blocks
            .Where(block => block.Header.Contains("resource \"aws_s3_bucket\"", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (buckets.Length == 0) return;

        var encryptionBlocks = blocks
            .Where(block => block.Header.Contains("resource \"aws_s3_bucket_server_side_encryption_configuration\"", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (var bucket in buckets)
        {
            if (S3EncryptionPattern().IsMatch(bucket.Text) ||
                encryptionBlocks.Any(encryption => ReferencesBucket(encryption.Text, bucket.Labels.ElementAtOrDefault(1))))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-TF004", "S3 encryption not visible",
                Severity.Medium, relativePath,
                "S3 bucket found but no matching server_side_encryption_configuration block is visible in this file.",
                bucket.StartLine,
                Confidence.Low));
        }
    }

    private static bool ReferencesBucket(string text, string? bucketName)
    {
        if (string.IsNullOrWhiteSpace(bucketName))
        {
            return false;
        }

        return Regex.IsMatch(
                   text,
                   $@"\baws_s3_bucket\.{Regex.Escape(bucketName)}(?:\.|\[|\s|$)",
                   RegexOptions.IgnoreCase) ||
               Regex.IsMatch(
                   text,
                   $@"\baws_s3_bucket\[\s*""{Regex.Escape(bucketName)}""\s*\]",
                   RegexOptions.IgnoreCase) ||
               Regex.IsMatch(text, $@"(?mi)^\s*bucket\s*=\s*""{Regex.Escape(bucketName)}""\s*$");
    }

    // ── TF005: provider version ───────────────────────────────────────

    private void CheckProviderVersion(
        string content,
        IReadOnlyList<TerraformBlock> blocks,
        string relativePath,
        List<Finding> findings)
    {
        if (!content.Contains("required_providers", StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var provider in ExtractProviderEntries(blocks))
        {
            var sourceMatch = ProviderSourcePattern().Match(provider.Text);
            if (!sourceMatch.Success || VersionConstraintPattern().IsMatch(provider.Text))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-TF005", "Provider missing version constraint",
                Severity.Medium, relativePath,
                $"Provider '{sourceMatch.Groups["source"].Value}' has no version constraint.",
                provider.StartLine,
                Confidence.Medium,
                AnalysisCategory.Dependencies));
        }
    }

    private static IReadOnlyList<TerraformBlock> ExtractProviderEntries(IReadOnlyList<TerraformBlock> blocks)
    {
        var requiredProviderBlocks = blocks
            .Where(block => block.Header.Contains("required_providers", StringComparison.OrdinalIgnoreCase))
            .Concat(blocks
                .Where(block => block.Header.StartsWith("terraform", StringComparison.OrdinalIgnoreCase))
                .SelectMany(block => TerraformBlockExtractor.Extract(block.Text))
                .Where(block => block.Header.Contains("required_providers", StringComparison.OrdinalIgnoreCase)))
            .GroupBy(block => (block.StartLine, block.Text))
            .Select(group => group.First());

        var providers = requiredProviderBlocks
            .SelectMany(block => TerraformBlockExtractor.ExtractAssignments(block.Text, block.StartLine))
            .Where(block => ProviderSourcePattern().IsMatch(block.Text))
            .GroupBy(block => (block.StartLine, block.Text))
            .Select(group => group.First())
            .ToArray();

        return providers;
    }

    // ── TF006: backend encryption ─────────────────────────────────────

    private void CheckBackendEncryption(IReadOnlyList<TerraformBlock> blocks, string relativePath, List<Finding> findings)
    {
        foreach (var backend in blocks.Where(block =>
                     block.Header.StartsWith("backend", StringComparison.OrdinalIgnoreCase) &&
                     block.Labels.FirstOrDefault()?.Equals("s3", StringComparison.OrdinalIgnoreCase) == true))
        {
            if (BackendEncryptTruePattern().IsMatch(backend.Text))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-TF006", "S3 backend missing encryption",
                Severity.Low, relativePath,
                "backend \"s3\" block does not set encrypt = true.",
                backend.StartLine,
                Confidence.Medium));
        }
    }

    // ── JSON helpers ──────────────────────────────────────────────────

    private static bool HasPublicCidrInJson(string resourceType, JsonElement element)
    {
        if (resourceType.Equals("aws_security_group", StringComparison.Ordinal))
        {
            return element.TryGetProperty("ingress", out var ingress) &&
                   HasPublicCidrBlocks(ingress);
        }

        if (!element.TryGetProperty("type", out var type) ||
            !type.ValueEquals("ingress"))
        {
            return false;
        }

        return HasPublicCidrBlocks(element);
    }

    private static bool HasPublicCidrBlocks(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (HasPublicCidrBlocks(item))
                {
                    return true;
                }
            }

            return false;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (element.TryGetProperty("cidr_blocks", out var cidrs))
        {
            if (cidrs.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

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

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High, AnalysisCategory category = AnalysisCategory.Infrastructure)
    {
        return new Finding(ruleId, title, category, severity, confidence, title,
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

    private static bool ShouldSkipTerraformFile(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');

        return normalized.Contains(".terraform/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/vendor/", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".terraform.lock.hcl", StringComparison.OrdinalIgnoreCase) ||
               IsLikelyTerraformFixturePath(normalized);
    }

    private static bool IsLikelyTerraformFixturePath(string normalizedPath) =>
        RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(normalizedPath);

    // ── Patterns ──────────────────────────────────────────────────────

    [GeneratedRegex(@"(?s)(?:ingress|egress)\s*\{[\s\S]*?\}")]
    private static partial Regex SecurityGroupBlockPattern();

    [GeneratedRegex(@"""?\b[Aa]ctions?\b""?\s*(?:=|:)\s*(?:\[\s*)?""\*""")]
    private static partial Regex IamActionStarPattern();

    [GeneratedRegex(@"""?\b[Rr]esources?\b""?\s*(?:=|:)\s*(?:\[\s*)?""\*""")]
    private static partial Regex IamResourceStarPattern();

    [GeneratedRegex(@"acl\s*=\s*""public-read(?:-write)?""", RegexOptions.IgnoreCase)]
    private static partial Regex PublicAclPattern();

    [GeneratedRegex(@"server_side_encryption_configuration", RegexOptions.IgnoreCase)]
    private static partial Regex S3EncryptionPattern();

    [GeneratedRegex(@"(?m)^\s*source\s*=\s*""(?<source>[^""]+)""\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ProviderSourcePattern();

    [GeneratedRegex(@"(?m)^\s*version\s*=\s*""[^""]+""\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex VersionConstraintPattern();

    [GeneratedRegex(@"(?mi)^\s*encrypt\s*=\s*true\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex BackendEncryptTruePattern();
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
        var inString = false;
        var escaped = false;
        var inBlockComment = false;
        var inLineComment = false;
        string? heredocTerminator = null;
        var atLineStart = true;

        while (i < content.Length)
        {
            var current = content[i];
            var next = i + 1 < content.Length ? content[i + 1] : '\0';

            if (heredocTerminator is not null)
            {
                if (atLineStart && IsHeredocTerminatorAt(content, i, heredocTerminator))
                {
                    heredocTerminator = null;
                }

                result.Append(current);
                atLineStart = current == '\n';
                i++;
                continue;
            }

            if (inLineComment)
            {
                if (current == '\n')
                {
                    inLineComment = false;
                    result.Append(current);
                    atLineStart = true;
                }
                else
                {
                    result.Append(' ');
                }

                i++;
                continue;
            }

            if (inBlockComment)
            {
                if (current == '*' && next == '/')
                {
                    result.Append(' ');
                    result.Append(' ');
                    i += 2;
                    inBlockComment = false;
                    continue;
                }

                result.Append(current == '\n' ? '\n' : ' ');
                atLineStart = current == '\n';
                i++;
                continue;
            }

            if (inString)
            {
                result.Append(current);
                if (escaped)
                {
                    escaped = false;
                }
                else if (current == '\\')
                {
                    escaped = true;
                }
                else if (current == '"')
                {
                    inString = false;
                }

                atLineStart = current == '\n';
                i++;
                continue;
            }

            if (current == '"')
            {
                inString = true;
                result.Append(current);
                atLineStart = false;
                i++;
                continue;
            }

            if (current == '/' && next == '*')
            {
                inBlockComment = true;
                result.Append(' ');
                result.Append(' ');
                i += 2;
                continue;
            }

            if (current == '#' || (current == '/' && next == '/'))
            {
                inLineComment = true;
                result.Append(' ');
                if (current == '/')
                {
                    result.Append(' ');
                    i += 2;
                }
                else
                {
                    i++;
                }

                continue;
            }

            if (current == '<' && next == '<' && TryReadHeredocTerminator(content, i, out var terminator))
            {
                heredocTerminator = terminator;
            }

            result.Append(current);
            atLineStart = current == '\n';
            i++;
        }

        return result.ToString();
    }

    private static bool TryReadHeredocTerminator(string content, int markerIndex, out string terminator)
    {
        terminator = string.Empty;
        var index = markerIndex + 2;
        if (index < content.Length && content[index] == '-')
        {
            index++;
        }

        while (index < content.Length && char.IsWhiteSpace(content[index]) && content[index] != '\n')
        {
            index++;
        }

        var start = index;
        while (index < content.Length && (char.IsLetterOrDigit(content[index]) || content[index] == '_'))
        {
            index++;
        }

        if (index == start)
        {
            return false;
        }

        terminator = content[start..index];
        return true;
    }

    private static bool IsHeredocTerminatorAt(string content, int index, string terminator)
    {
        var cursor = index;
        while (cursor < content.Length && (content[cursor] == ' ' || content[cursor] == '\t'))
        {
            cursor++;
        }

        if (!content.AsSpan(cursor).StartsWith(terminator, StringComparison.Ordinal))
        {
            return false;
        }

        cursor += terminator.Length;
        return cursor >= content.Length ||
               content[cursor] == '\r' ||
               content[cursor] == '\n';
    }
}
