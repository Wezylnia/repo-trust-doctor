using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

/// <summary>
/// TRUST-TF007: Terraform dependency lockfile is missing.
/// Directory-scoped — checks whether a .terraform.lock.hcl exists
/// alongside .tf files that declare required_providers.
/// </summary>
internal static class TerraformLockfileChecks
{
    public static void CheckAll(
        string repositoryPath,
        string relativeDirectory,
        string _,
        List<Finding> findings)
    {
        var directoryPath = string.IsNullOrEmpty(relativeDirectory) || relativeDirectory == "."
            ? repositoryPath
            : Path.GetFullPath(Path.Combine(repositoryPath, relativeDirectory));

        var requiredProvidersEvidence = FindRequiredProvidersEvidence(
            repositoryPath,
            directoryPath);

        if (requiredProvidersEvidence is null)
        {
            return;
        }

        var lockfilePath = Path.Combine(directoryPath, ".terraform.lock.hcl");
        if (File.Exists(lockfilePath))
        {
            return;
        }

        var normalizedDirectory = string.IsNullOrEmpty(relativeDirectory) || relativeDirectory == "."
            ? "."
            : relativeDirectory;
        var identityKey = $"tf007|{normalizedDirectory}";

        findings.Add(new Finding(
            "TRUST-TF007",
            "Terraform dependency lockfile is missing",
            AnalysisCategory.Dependencies,
            Severity.Medium,
            Confidence.High,
            $"No .terraform.lock.hcl found in directory '{normalizedDirectory}' while Terraform configuration declares required_providers.",
            [new Evidence(
                "terraform-lockfile",
                $"Missing .terraform.lock.hcl for Terraform root/module directory '{normalizedDirectory}'.",
                requiredProvidersEvidence.Value.FilePath,
                requiredProvidersEvidence.Value.LineNumber)],
            new Recommendation("Run 'terraform providers lock' to create a .terraform.lock.hcl for reproducible provider versions."),
            IdentityKey: identityKey));
    }

    private static (string FilePath, int LineNumber)? FindRequiredProvidersEvidence(
        string repositoryPath,
        string directoryPath)
    {
        foreach (var file in Directory
                     .EnumerateFiles(directoryPath, "*.tf", SearchOption.TopDirectoryOnly)
                     .OrderBy(static path => path, StringComparer.Ordinal))
        {
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var relativePath = Path.GetRelativePath(repositoryPath, file).Replace('\\', '/');
            var content = File.ReadAllText(file);
            var sanitized = CommentStripper.StripComments(content);
            var requiredProviders = TerraformBlockExtractor
                .Extract(sanitized)
                .FirstOrDefault(static block =>
                    block.Header.StartsWith(
                        "required_providers",
                        StringComparison.OrdinalIgnoreCase));

            if (requiredProviders is not null)
            {
                return (relativePath, requiredProviders.StartLine);
            }
        }

        return null;
    }
}
