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
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists || info.Length > maxBytes)
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

    private static bool HasExcludedPathPart(string filePath)
    {
        return filePath
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(part => ExcludedDirectoryNames.Contains(part, StringComparer.OrdinalIgnoreCase));
    }
}
