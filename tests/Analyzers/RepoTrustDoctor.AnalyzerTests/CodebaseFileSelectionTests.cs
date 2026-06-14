using RepoTrustDoctor.Analyzers.Codebase;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CodebaseFileSelectionTests
{
    [Fact]
    public void Select_BalancesLimitedFilesAcrossMonorepoPartitions()
    {
        using var repository = TemporaryRepository.Create();
        var candidates = Enumerable.Range(0, 8)
            .SelectMany(package => Enumerable.Range(0, 4)
                .Select(file => Path.Combine(repository.Path, "packages", $"package-{package}", "src", $"File{file}.cs")))
            .ToArray();

        var result = CodebaseFileSelection.Select(repository.Path, candidates, maximumFiles: 8);

        Assert.Equal(8, result.Files.Count);
        Assert.Equal(8, result.EligiblePartitionCount);
        Assert.Equal(8, result.SelectedPartitionCount);
        Assert.Equal(8, result.Files.Select(GetPackageName).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Select_IsDeterministicWhenEnumerationOrderChanges()
    {
        using var repository = TemporaryRepository.Create();
        var candidates = Enumerable.Range(0, 20)
            .Select(index => Path.Combine(repository.Path, "services", $"service-{index % 5}", "src", $"File{index}.cs"))
            .ToArray();

        var forward = CodebaseFileSelection.Select(repository.Path, candidates, maximumFiles: 11);
        var reverse = CodebaseFileSelection.Select(repository.Path, candidates.Reverse(), maximumFiles: 11);

        Assert.Equal(forward.Files, reverse.Files);
    }

    [Fact]
    public void Select_PrefersHigherPriorityFileWithinEachPartition()
    {
        using var repository = TemporaryRepository.Create();
        var candidates = new[]
        {
            Path.Combine(repository.Path, "packages", "a", "tools", "Build.cs"),
            Path.Combine(repository.Path, "packages", "a", "src", "Product.cs"),
            Path.Combine(repository.Path, "packages", "b", "tools", "Build.cs"),
            Path.Combine(repository.Path, "packages", "b", "src", "Product.cs")
        };

        var result = CodebaseFileSelection.Select(
            repository.Path,
            candidates,
            maximumFiles: 2,
            file => file.Contains($"{Path.DirectorySeparatorChar}tools{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) ? 1 : 0);

        Assert.All(result.Files, file => Assert.Contains($"{Path.DirectorySeparatorChar}src{Path.DirectorySeparatorChar}", file));
    }

    private static string GetPackageName(string path)
    {
        var segments = path.Replace('\\', '/').Split('/');
        var packagesIndex = Array.FindIndex(segments, segment => segment.Equals("packages", StringComparison.OrdinalIgnoreCase));
        return segments[packagesIndex + 1];
    }
}
