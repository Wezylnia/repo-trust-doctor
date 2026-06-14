namespace RepoTrustDoctor.Analysis.Abstractions;

public static class RepositoryFileSystem
{
    public const long DefaultMaxReadableFileBytes = 512 * 1024;

    private static readonly string[] ExcludedDirectoryNames =
    [
        ".git",
        ".hg",
        ".svn",
        ".repo-trust",
        "private-docs",
        "bin",
        "obj",
        "node_modules",
        "vendor",
        "third_party",
        "third-party",
        "thirdparty",
        "external",
        ".gradle",
        ".terraform",
        ".dart_tool",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".next",
        ".nuxt",
        "Pods",
        "DerivedData"
    ];

    private static readonly AsyncLocal<RepositoryFileIndex?> ActiveIndex = new();

    public static IEnumerable<string> EnumerateFiles(string root, string searchPattern = "*", SearchOption searchOption = SearchOption.AllDirectories)
    {
        var fullRoot = Path.GetFullPath(root);
        if (ActiveIndex.Value?.TryEnumerateFiles(fullRoot, searchPattern, searchOption, out var indexedFiles) == true)
        {
            return indexedFiles;
        }

        return EnumerateFilesUncached(fullRoot, searchPattern, searchOption);
    }

    public static IDisposable UseFileIndex(string repositoryRoot)
    {
        var previous = ActiveIndex.Value;
        ActiveIndex.Value = new RepositoryFileIndex(Path.GetFullPath(repositoryRoot));
        return new FileIndexScope(previous);
    }

    public static bool CanReadAsText(string filePath, long maxBytes = DefaultMaxReadableFileBytes)
    {
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists ||
                info.Length > maxBytes ||
                info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return false;
            }

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var bytesToRead = (int)Math.Min(4096, stream.Length);
                if (bytesToRead == 0)
                {
                    return true;
                }

                var buffer = new byte[bytesToRead];
                var bytesRead = stream.Read(buffer, 0, bytesToRead);
                for (var i = 0; i < bytesRead; i++)
                {
                    if (buffer[i] == 0)
                    {
                        return false;
                    }
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> EnumerateFilesUncached(string root, string searchPattern, SearchOption searchOption)
    {
        if (!Directory.Exists(root))
        {
            yield break;
        }

        foreach (var file in SafeEnumerateFiles(root, searchPattern))
        {
            yield return file;
        }

        if (searchOption != SearchOption.AllDirectories)
        {
            yield break;
        }

        foreach (var directory in SafeEnumerateDirectories(root))
        {
            foreach (var file in EnumerateFilesUncached(directory, searchPattern, searchOption))
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> SafeEnumerateFiles(string root, string searchPattern)
    {
        try
        {
            return Directory.EnumerateFiles(root, searchPattern, CreateTopDirectoryOnlyOptions());
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string root)
    {
        try
        {
            return Directory
                .EnumerateDirectories(root, "*", CreateTopDirectoryOnlyOptions())
                .Where(directory => !IsExcludedDirectory(directory));
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static EnumerationOptions CreateTopDirectoryOnlyOptions() => new()
    {
        AttributesToSkip = FileAttributes.ReparsePoint,
        IgnoreInaccessible = true,
        RecurseSubdirectories = false
    };

    private static bool IsExcludedDirectory(string directoryPath) =>
        IsExcludedDirectoryName(Path.GetFileName(directoryPath));

    public static bool IsExcludedDirectoryName(string directoryName) =>
        ExcludedDirectoryNames.Contains(directoryName, StringComparer.OrdinalIgnoreCase);

    private sealed class RepositoryFileIndex
    {
        private readonly string repositoryRoot;
        private readonly Lazy<IReadOnlyList<string>> files;

        public RepositoryFileIndex(string repositoryRoot)
        {
            this.repositoryRoot = TrimTrailingDirectorySeparators(repositoryRoot);
            files = new Lazy<IReadOnlyList<string>>(
                () => EnumerateFilesUncached(this.repositoryRoot, "*", SearchOption.AllDirectories).ToArray(),
                LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public bool TryEnumerateFiles(
            string root,
            string searchPattern,
            SearchOption searchOption,
            out IEnumerable<string> indexedFiles)
        {
            var normalizedRoot = TrimTrailingDirectorySeparators(root);
            if (!IsSameOrChildPath(normalizedRoot, repositoryRoot))
            {
                indexedFiles = [];
                return false;
            }

            if (!Directory.Exists(normalizedRoot))
            {
                indexedFiles = [];
                return true;
            }

            indexedFiles = files.Value
                .Where(file => IsInsideRequestedRoot(file, normalizedRoot, searchOption))
                .Where(file => MatchesSearchPattern(file, searchPattern));
            return true;
        }

        private static bool IsInsideRequestedRoot(string file, string root, SearchOption searchOption)
        {
            if (searchOption == SearchOption.TopDirectoryOnly)
            {
                var directory = Path.GetDirectoryName(file);
                return directory is not null &&
                       string.Equals(TrimTrailingDirectorySeparators(directory), root, PathComparison);
            }

            return IsSameOrChildPath(file, root);
        }
    }

    private sealed class FileIndexScope(RepositoryFileIndex? previous) : IDisposable
    {
        public void Dispose()
        {
            ActiveIndex.Value = previous;
        }
    }

    private static bool MatchesSearchPattern(string filePath, string searchPattern) =>
        string.IsNullOrWhiteSpace(searchPattern) ||
        searchPattern == "*" ||
        System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(
            searchPattern,
            Path.GetFileName(filePath),
            ignoreCase: PathComparison == StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrChildPath(string path, string parent)
    {
        var normalizedPath = TrimTrailingDirectorySeparators(path);
        var normalizedParent = TrimTrailingDirectorySeparators(parent);
        return string.Equals(normalizedPath, normalizedParent, PathComparison) ||
               normalizedPath.StartsWith(EnsureTrailingDirectorySeparator(normalizedParent), PathComparison);
    }

    private static string EnsureTrailingDirectorySeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;

    private static string TrimTrailingDirectorySeparators(string path)
    {
        var root = Path.GetPathRoot(path) ?? string.Empty;
        while (path.Length > root.Length &&
               (path[^1] == Path.DirectorySeparatorChar || path[^1] == Path.AltDirectorySeparatorChar))
        {
            path = path[..^1];
        }

        return path;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}
