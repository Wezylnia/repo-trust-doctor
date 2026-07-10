using System.Collections.Concurrent;

namespace RepoTrustDoctor.Analysis.Abstractions;

public sealed record RepositoryFileEntry(
    string FullPath,
    string RelativePath,
    string Extension,
    long Length,
    DateTimeOffset LastWriteTimeUtc,
    RepositoryPathClassification Classification);

public static class RepositoryFileSystem
{
    public const long DefaultMaxReadableFileBytes = 512 * 1024;
    public const long DefaultMaxCachedTextBytes = 64L * 1024 * 1024;

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

    public static IEnumerable<RepositoryFileEntry> EnumerateFileEntries(
        string root,
        string searchPattern = "*",
        SearchOption searchOption = SearchOption.AllDirectories)
    {
        var fullRoot = Path.GetFullPath(root);
        if (ActiveIndex.Value?.TryEnumerateFileEntries(fullRoot, searchPattern, searchOption, out var entries) == true)
        {
            return entries;
        }

        return EnumerateFilesUncached(fullRoot, searchPattern, searchOption)
            .Select(file => CreateFileEntry(fullRoot, file));
    }

    public static async ValueTask<string?> ReadAllTextAsync(
        string filePath,
        CancellationToken cancellationToken,
        long maxBytes = DefaultMaxReadableFileBytes)
    {
        var fullPath = Path.GetFullPath(filePath);
        if (!CanReadAsText(fullPath, maxBytes))
        {
            return null;
        }

        if (ActiveIndex.Value?.Contains(fullPath) == true)
        {
            return await ActiveIndex.Value.ReadAllTextAsync(fullPath, maxBytes, cancellationToken);
        }

        try
        {
            return await File.ReadAllTextAsync(fullPath, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
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

    private static RepositoryFileEntry CreateFileEntry(string repositoryRoot, string filePath)
    {
        try
        {
            var info = new FileInfo(filePath);
            var relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace('\\', '/');
            return new RepositoryFileEntry(
                filePath,
                relativePath,
                info.Extension,
                info.Exists ? info.Length : 0,
                info.Exists ? info.LastWriteTimeUtc : DateTimeOffset.MinValue,
                RepositoryPathClassifier.Classify(relativePath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            var relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace('\\', '/');
            return new RepositoryFileEntry(
                filePath,
                relativePath,
                Path.GetExtension(filePath),
                0,
                DateTimeOffset.MinValue,
                RepositoryPathClassifier.Classify(relativePath));
        }
    }

    private sealed class RepositoryFileIndex
    {
        private readonly string repositoryRoot;
        private readonly Lazy<IReadOnlyList<string>> files;
        private readonly Lazy<IReadOnlyList<RepositoryFileEntry>> entries;
        private readonly ConcurrentDictionary<TextCacheKey, Lazy<Task<CachedText>>> textCache = new();
        private long cachedTextBytes;

        public RepositoryFileIndex(string repositoryRoot)
        {
            this.repositoryRoot = TrimTrailingDirectorySeparators(repositoryRoot);
            files = new Lazy<IReadOnlyList<string>>(
                () => EnumerateFilesUncached(this.repositoryRoot, "*", SearchOption.AllDirectories).ToArray(),
                LazyThreadSafetyMode.ExecutionAndPublication);
            entries = new Lazy<IReadOnlyList<RepositoryFileEntry>>(
                () => files.Value.Select(file => CreateFileEntry(this.repositoryRoot, file)).ToArray(),
                LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public bool Contains(string fullPath) => IsSameOrChildPath(fullPath, repositoryRoot);

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

        public bool TryEnumerateFileEntries(
            string root,
            string searchPattern,
            SearchOption searchOption,
            out IEnumerable<RepositoryFileEntry> indexedEntries)
        {
            var normalizedRoot = TrimTrailingDirectorySeparators(root);
            if (!IsSameOrChildPath(normalizedRoot, repositoryRoot))
            {
                indexedEntries = [];
                return false;
            }

            if (!Directory.Exists(normalizedRoot))
            {
                indexedEntries = [];
                return true;
            }

            indexedEntries = entries.Value
                .Where(entry => IsInsideRequestedRoot(entry.FullPath, normalizedRoot, searchOption))
                .Where(entry => MatchesSearchPattern(entry.FullPath, searchPattern));
            return true;
        }

        public async ValueTask<string?> ReadAllTextAsync(
            string fullPath,
            long maxBytes,
            CancellationToken cancellationToken)
        {
            var key = new TextCacheKey(fullPath, maxBytes);
            var lazy = textCache.GetOrAdd(
                key,
                cacheKey => new Lazy<Task<CachedText>>(
                    () => LoadTextAsync(cacheKey),
                    LazyThreadSafetyMode.ExecutionAndPublication));
            var cached = await lazy.Value.WaitAsync(cancellationToken);
            if (!cached.Keep)
            {
                textCache.TryRemove(key, out _);
            }

            return cached.Text;
        }

        private async Task<CachedText> LoadTextAsync(TextCacheKey key)
        {
            string? text;
            try
            {
                text = await File.ReadAllTextAsync(key.FullPath, CancellationToken.None);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new CachedText(null, Keep: false);
            }

            var bytes = checked((long)text.Length * sizeof(char));
            var total = Interlocked.Add(ref cachedTextBytes, bytes);
            if (total <= DefaultMaxCachedTextBytes)
            {
                return new CachedText(text, Keep: true);
            }

            Interlocked.Add(ref cachedTextBytes, -bytes);
            return new CachedText(text, Keep: false);
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

        private readonly record struct TextCacheKey(string FullPath, long MaxBytes);

        private sealed record CachedText(string? Text, bool Keep);
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
