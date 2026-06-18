using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Terraform;

internal sealed record RequiredProvidersEvidence(
    string FilePath,
    int LineNumber);

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
        var lockfilePath = Path.Combine(directoryPath, ".terraform.lock.hcl");

        if (File.Exists(lockfilePath) || !Directory.Exists(directoryPath))
        {
            return;
        }

        var pathComparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

        RequiredProvidersEvidence? evidence = null;
        foreach (var file in Directory
                     .EnumerateFiles(directoryPath, "*.tf", SearchOption.TopDirectoryOnly)
                     .Where(RepositoryFileSystem.CanReadAsText)
                     .OrderBy(file => Path.GetRelativePath(repositoryPath, file), pathComparer))
        {
            var relativePath = Path.GetRelativePath(repositoryPath, file).Replace('\\', '/');
            evidence = TryFindRequiredProviders(file, relativePath);
            if (evidence is not null)
            {
                break;
            }
        }

        if (evidence is null)
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

    private static RequiredProvidersEvidence? TryFindRequiredProviders(
        string fullPath,
        string relativePath)
    {
        string content;
        try
        {
            content = File.ReadAllText(fullPath);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }

        var sanitized = CommentStripper.StripComments(content);
        foreach (var terraformBlock in TerraformBlockExtractor
                     .Extract(sanitized)
                     .Where(static block => block.Header.Equals("terraform", StringComparison.OrdinalIgnoreCase)))
        {
            var requiredProviders = TerraformBlockExtractor
                .Extract(terraformBlock.Text)
                .FirstOrDefault(static block =>
                    block.Header.Equals("required_providers", StringComparison.OrdinalIgnoreCase));

            if (requiredProviders is not null)
            {
                return new RequiredProvidersEvidence(
                    relativePath,
                    terraformBlock.StartLine + requiredProviders.StartLine - 1);
            }
        }

        return null;
    }
}
