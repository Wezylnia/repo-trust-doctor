using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.Codebase;

internal sealed class ImportGraphFileIndex
{
    private readonly HashSet<string> knownFiles;
    private readonly Dictionary<string, string?> uniqueSuffixes;
    private readonly IReadOnlyList<GoModule> goModules;
    private readonly IReadOnlyList<string> sourceExtensions;

    public ImportGraphFileIndex(
        IEnumerable<string> files,
        string repositoryPath,
        IReadOnlyList<string> sourceExtensions)
    {
        knownFiles = files.ToHashSet(StringComparer.OrdinalIgnoreCase);
        uniqueSuffixes = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        goModules = ReadGoModules(repositoryPath);
        this.sourceExtensions = sourceExtensions;

        foreach (var file in knownFiles)
        {
            AddSuffixes(file);
        }
    }

    public bool Contains(string normalizedPath) => knownFiles.Contains(normalizedPath);

    public string? ResolveGoPackage(string importPath)
    {
        var module = goModules
            .Where(candidate =>
                importPath.Equals(candidate.ModulePath, StringComparison.Ordinal) ||
                importPath.StartsWith(candidate.ModulePath + "/", StringComparison.Ordinal))
            .OrderByDescending(candidate => candidate.ModulePath.Length)
            .FirstOrDefault();
        if (module is null)
        {
            return null;
        }

        var packageSuffix = importPath[module.ModulePath.Length..].Trim('/');
        var packageDirectory = string.IsNullOrWhiteSpace(module.RootDirectory)
            ? packageSuffix
            : string.IsNullOrWhiteSpace(packageSuffix)
                ? module.RootDirectory
                : $"{module.RootDirectory}/{packageSuffix}";
        var candidates = knownFiles
            .Where(file =>
                file.EndsWith(".go", StringComparison.OrdinalIgnoreCase) &&
                !file.EndsWith("_test.go", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    Path.GetDirectoryName(file)?.Replace('\\', '/') ?? string.Empty,
                    packageDirectory,
                    StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    public string? ResolveSuffixPath(string modulePath)
    {
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return null;
        }

        foreach (var extension in sourceExtensions)
        {
            var suffix = modulePath.EndsWith(extension, StringComparison.OrdinalIgnoreCase)
                ? modulePath
                : modulePath + extension;
            if (uniqueSuffixes.TryGetValue(suffix, out var match))
            {
                return match;
            }
        }

        return null;
    }

    private void AddSuffixes(string file)
    {
        var parts = file.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var index = 0; index < parts.Length; index++)
        {
            AddUniqueSuffix(string.Join("/", parts[index..]), file);
        }
    }

    private void AddUniqueSuffix(string suffix, string file)
    {
        if (!uniqueSuffixes.TryGetValue(suffix, out var existing))
        {
            uniqueSuffixes[suffix] = file;
            return;
        }

        if (!string.Equals(existing, file, StringComparison.OrdinalIgnoreCase))
        {
            uniqueSuffixes[suffix] = null;
        }
    }

    private static IReadOnlyList<GoModule> ReadGoModules(string repositoryPath)
    {
        var modules = new List<GoModule>();
        foreach (var goMod in RepositoryFileSystem.EnumerateFiles(repositoryPath, "go.mod"))
        {
            if (!RepositoryFileSystem.CanReadAsText(goMod))
            {
                continue;
            }

            try
            {
                var moduleLine = File.ReadLines(goMod)
                    .Select(line => line.Trim())
                    .FirstOrDefault(line => line.StartsWith("module ", StringComparison.Ordinal));
                var modulePath = moduleLine?["module ".Length..]
                    .Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault();
                if (string.IsNullOrWhiteSpace(modulePath))
                {
                    continue;
                }

                var rootDirectory = Path.GetDirectoryName(
                    Path.GetRelativePath(repositoryPath, goMod).Replace('\\', '/')) ?? string.Empty;
                modules.Add(new GoModule(modulePath, rootDirectory.Replace('\\', '/')));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
            {
            }
        }

        return modules;
    }

    private sealed record GoModule(string ModulePath, string RootDirectory);
}
