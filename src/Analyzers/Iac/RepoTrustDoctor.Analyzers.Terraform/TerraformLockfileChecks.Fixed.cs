using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

internal sealed record RequiredProvidersEvidence(
    string FilePath,
    int LineNumber);

internal static class TerraformLockfileDirectoryChecks
{
    public static bool TryFindRequiredProviders(
        string sanitizedContent,
        string relativePath,
        out RequiredProvidersEvidence? evidence)
    {
        var block = TerraformBlockExtractor
            .Extract(sanitizedContent)
            .FirstOrDefault(static candidate =>
                candidate.Header.StartsWith(
                    "required_providers",
                    StringComparison.OrdinalIgnoreCase));

        if (block is null)
        {
            evidence = null;
            return false;
        }

        evidence = new RequiredProvidersEvidence(relativePath, block.StartLine);
        return true;
    }

    public static void CheckDirectory(
        string repositoryPath,
        string relativeDirectory,
        RequiredProvidersEvidence evidence,
        List<Finding> findings)
    {
        var directoryPath = string.IsNullOrEmpty(relativeDirectory) || relativeDirectory == "."
            ? repositoryPath
            : Path.GetFullPath(Path.Combine(repositoryPath, relativeDirectory));
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
                evidence.FilePath,
                evidence.LineNumber)],
            new Recommendation("Run 'terraform providers lock' to create a .terraform.lock.hcl for reproducible provider versions."),
            IdentityKey: identityKey));
    }
}
