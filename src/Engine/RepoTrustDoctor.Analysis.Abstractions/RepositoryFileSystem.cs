namespace RepoTrustDoctor.Analysis.Abstractions;

public static class RepositoryFileSystem
{
    public const long DefaultMaxReadableFileBytes = 512 * 1024;

    private static readonly string[] ExcludedDirectoryNames = [".git", "bin", "obj", "node_modules", ".repo-trust", "private-docs"];

    public static IEnumerable<string> EnumerateFiles(string root, string searchPattern = "*", SearchOption searchOption = SearchOption.AllDirectories)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = searchOption == SearchOption.AllDirectories,
            IgnoreInaccessible = true
        };

        return Directory.EnumerateFiles(root, searchPattern, options)
            .Where(file => !HasExcludedPathPart(file));
    }

    public static bool CanReadAsText(string filePath, long maxBytes = DefaultMaxReadableFileBytes)
    {
        var info = new FileInfo(filePath);
        return info.Exists && info.Length <= maxBytes;
    }

    private static bool HasExcludedPathPart(string filePath)
    {
        return filePath
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(part => ExcludedDirectoryNames.Contains(part, StringComparer.OrdinalIgnoreCase));
    }
}
