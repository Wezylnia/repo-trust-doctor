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
        string repositoryPath, string relativeDirectory, string tfContent, List<Finding> findings)
    {
        // Only trigger when the .tf file declares required_providers.
        if (!tfContent.Contains("required_providers", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var dirPath = string.IsNullOrEmpty(relativeDirectory) || relativeDirectory == "."
            ? repositoryPath
            : Path.GetFullPath(Path.Combine(repositoryPath, relativeDirectory));
        var lockfilePath = Path.Combine(dirPath, ".terraform.lock.hcl");

        if (File.Exists(lockfilePath))
        {
            return;
        }

        var relativeDir = string.IsNullOrEmpty(relativeDirectory) || relativeDirectory == "."
            ? "."
            : relativeDirectory;
        var identityKey = $"tf007|{relativeDir}";

        findings.Add(new Finding(
            "TRUST-TF007",
            "Terraform dependency lockfile is missing",
            AnalysisCategory.Dependencies,
            Severity.Medium,
            Confidence.High,
            $"No .terraform.lock.hcl found in directory '{relativeDirectory}' while .tf files declare required_providers.",
            [new Evidence("terraform-lockfile", $"Missing .terraform.lock.hcl for Terraform root/module directory.", relativeDirectory)],
            new Recommendation("Run 'terraform providers lock' to create a .terraform.lock.hcl for reproducible provider versions."),
            IdentityKey: identityKey));
    }
}
