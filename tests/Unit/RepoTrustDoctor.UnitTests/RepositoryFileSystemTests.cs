using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.UnitTests;

public sealed class RepositoryFileSystemTests
{
    [Fact]
    public void EnumerateFilesSkipsExcludedDirectoriesBeforeReturningFiles()
    {
        using var directory = TemporaryDirectory.Create();
        WriteFile(directory.Path, "README.md", "# sample");
        WriteFile(directory.Path, "src/App.cs", "public sealed class App { }");
        WriteFile(directory.Path, "packages/app/package.json", "{}");
        WriteFile(directory.Path, "coverage/coverage.xml", "<coverage />");
        WriteFile(directory.Path, ".git/objects/aa/hidden", "git object");
        WriteFile(directory.Path, "node_modules/pkg/package.json", "{}");
        WriteFile(directory.Path, "vendor/pkg/ignored.go", "ignored");
        WriteFile(directory.Path, "third_party/pkg/ignored.go", "ignored");
        WriteFile(directory.Path, ".terraform/providers/provider.bin", "provider");
        WriteFile(directory.Path, "private-docs/notes.md", "private");

        var files = RepositoryFileSystem
            .EnumerateFiles(directory.Path)
            .Select(file => Relative(directory.Path, file))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(["coverage/coverage.xml", "packages/app/package.json", "README.md", "src/App.cs"], files);
    }

    [Fact]
    public void EnumerateFilesKeepsTopDirectoryOnlySearchesAtRoot()
    {
        using var directory = TemporaryDirectory.Create();
        WriteFile(directory.Path, "README.md", "# sample");
        WriteFile(directory.Path, "docs/README.md", "# docs");

        var files = RepositoryFileSystem
            .EnumerateFiles(directory.Path, "*.md", SearchOption.TopDirectoryOnly)
            .Select(file => Relative(directory.Path, file))
            .ToArray();

        Assert.Equal(["README.md"], files);
    }

    [Fact]
    public void EnumerateFilesAllowsRepositoryRootsInsideIgnoredParentDirectories()
    {
        using var directory = TemporaryDirectory.Create();
        var repositoryRoot = Path.Combine(directory.Path, ".repo-trust", "corpus", "sample");
        WriteFile(repositoryRoot, "src/App.cs", "public sealed class App { }");
        WriteFile(repositoryRoot, ".git/objects/aa/hidden", "git object");

        var files = RepositoryFileSystem
            .EnumerateFiles(repositoryRoot)
            .Select(file => Relative(repositoryRoot, file))
            .ToArray();

        Assert.Equal(["src/App.cs"], files);
    }

    [Fact]
    public void FileIndexPreservesSearchPatternAndSearchOptionSemantics()
    {
        using var directory = TemporaryDirectory.Create();
        WriteFile(directory.Path, "Dockerfile", "FROM alpine");
        WriteFile(directory.Path, "src/App.cs", "public sealed class App { }");
        WriteFile(directory.Path, "src/App.Tests.cs", "public sealed class AppTests { }");
        WriteFile(directory.Path, "src/nested/App.py", "print('hello')");

        using var index = RepositoryFileSystem.UseFileIndex(directory.Path);

        var topLevelDockerfiles = RepositoryFileSystem
            .EnumerateFiles(directory.Path, "Dockerfile*", SearchOption.TopDirectoryOnly)
            .Select(file => Relative(directory.Path, file))
            .ToArray();
        var sourceFiles = RepositoryFileSystem
            .EnumerateFiles(Path.Combine(directory.Path, "src"), "*.cs")
            .Select(file => Relative(directory.Path, file))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(["Dockerfile"], topLevelDockerfiles);
        Assert.Equal(["src/App.cs", "src/App.Tests.cs"], sourceFiles);
    }

    [Fact]
    public void FileIndexFallsBackForRootsOutsideIndexedRepository()
    {
        using var indexed = TemporaryDirectory.Create();
        using var external = TemporaryDirectory.Create();
        WriteFile(indexed.Path, "src/App.cs", "public sealed class App { }");
        WriteFile(external.Path, "external.txt", "outside");

        using var index = RepositoryFileSystem.UseFileIndex(indexed.Path);

        var files = RepositoryFileSystem
            .EnumerateFiles(external.Path)
            .Select(file => Relative(external.Path, file))
            .ToArray();

        Assert.Equal(["external.txt"], files);
    }

    [Fact]
    public void EnumerateFilesSkipsDirectorySymlinks()
    {
        using var repository = TemporaryDirectory.Create();
        using var outside = TemporaryDirectory.Create();
        WriteFile(repository.Path, "README.md", "# sample");
        WriteFile(outside.Path, "secret.txt", "outside");

        var linkPath = Path.Combine(repository.Path, "linked");
        if (!TryCreateDirectorySymlink(linkPath, outside.Path))
        {
            return;
        }

        var files = RepositoryFileSystem
            .EnumerateFiles(repository.Path)
            .Select(file => Relative(repository.Path, file))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(["README.md"], files);
    }

    [Fact]
    public void CanReadAsTextRejectsFileSymlinks()
    {
        using var repository = TemporaryDirectory.Create();
        using var outside = TemporaryDirectory.Create();
        WriteFile(outside.Path, "secret.txt", "outside");

        var linkPath = Path.Combine(repository.Path, "secret-link.txt");
        if (!TryCreateFileSymlink(linkPath, Path.Combine(outside.Path, "secret.txt")))
        {
            return;
        }

        Assert.False(RepositoryFileSystem.CanReadAsText(linkPath));
    }

    private static void WriteFile(string root, string relativePath, string content)
    {
        var path = Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static string Relative(string root, string filePath) =>
        Path.GetRelativePath(root, filePath).Replace(Path.DirectorySeparatorChar, '/');

    private static bool TryCreateDirectorySymlink(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryCreateFileSymlink(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
