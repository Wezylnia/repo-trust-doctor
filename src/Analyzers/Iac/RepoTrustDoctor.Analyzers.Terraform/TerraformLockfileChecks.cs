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

        var evidence = Directory
            .EnumerateFiles(directoryPath, "*.tf", SearchOption.TopDirectoryOnly)
            .Where(RepositoryFileSystem.CanReadAsText)
            .Select(file => new
            {
                FullPath = file,
                RelativePath = Path.GetRelativePath(repositoryPath, file).Replace('\\', '/')
            })
            .OrderBy(candidate => candidate.RelativePath, pathComparer)
            .Select(candidate => TryFindRequiredProviders(candidate.FullPath, candidate.RelativePath))
            .FirstOrDefault(static candidate => candidate is not null);

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
        var requiredProviders = TerraformBlockExtractor
            .Extract(sanitized)
            .FirstOrDefault(static block =>
                block.Header.StartsWith(
                    "required_providers",
                    StringComparison.OrdinalIgnoreCase));

        return requiredProviders is null
            ? null
            : new RequiredProvidersEvidence(relativePath, requiredProviders.StartLine);
    }
}
