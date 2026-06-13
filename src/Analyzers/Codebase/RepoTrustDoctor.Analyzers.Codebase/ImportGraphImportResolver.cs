using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class ImportGraphAnalyzer
{
    private static List<string> ParseImports(
        string text,
        string extension,
        string sourceRelativePath,
        ImportGraphFileIndex fileIndex)
    {
        var imports = new List<string>();

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();

            switch (extension)
            {
                case ".cs":
                    ParseCSharpImport(trimmed, imports, fileIndex);
                    break;
                case ".ts" or ".tsx" or ".js" or ".jsx":
                    ParseJavaScriptImport(trimmed, imports, sourceRelativePath, fileIndex);
                    break;
                case ".py":
                    ParsePythonImport(trimmed, imports, fileIndex);
                    break;
                case ".java":
                    ParseJavaImport(trimmed, imports, fileIndex);
                    break;
                case ".go":
                    ParseGoImport(trimmed, imports, fileIndex);
                    break;
                case ".rs":
                    ParseRustImport(trimmed, imports, fileIndex);
                    break;
            }
        }

        return imports;
    }

    private static void ParseCSharpImport(string line, List<string> imports, ImportGraphFileIndex fileIndex)
    {
        if (!line.StartsWith("using ", StringComparison.Ordinal))
        {
            return;
        }

        var match = CSharpUsingRegex().Match(line);
        if (!match.Success)
        {
            return;
        }

        var ns = match.Groups["ns"].Value;
        if (ns.StartsWith("System", StringComparison.Ordinal) ||
            ns.StartsWith("Microsoft", StringComparison.Ordinal))
        {
            return;
        }

        var resolved = fileIndex.ResolveSuffixPath(ns.Replace('.', '/'));
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static void ParseJavaScriptImport(string line, List<string> imports, string sourceRelativePath, ImportGraphFileIndex fileIndex)
    {
        Match? match = null;

        if (line.StartsWith("import", StringComparison.Ordinal))
        {
            if (IsTypeOnlyJavaScriptImport(line))
            {
                return;
            }

            match = JsImportFromRegex().Match(line);
            if (!match.Success)
            {
                match = JsDynamicImportRegex().Match(line);
            }
        }
        else if (line.Contains("require(", StringComparison.Ordinal))
        {
            match = JsRequireRegex().Match(line);
        }

        if (match is not { Success: true })
        {
            return;
        }

        var path = match.Groups["path"].Value;
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('.'))
        {
            return;
        }

        var resolved = ResolveRelativePath(sourceRelativePath, path, fileIndex);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static bool IsTypeOnlyJavaScriptImport(string line) =>
        line.StartsWith("import type ", StringComparison.Ordinal) ||
        JsTypeOnlyNamedImportRegex().IsMatch(line);

    private static void ParsePythonImport(string line, List<string> imports, ImportGraphFileIndex fileIndex)
    {
        if (line.StartsWith("from ", StringComparison.Ordinal))
        {
            var match = PythonFromImportRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["module"].Value, fileIndex, imports);
            }
        }
        else if (line.StartsWith("import ", StringComparison.Ordinal))
        {
            var match = PythonImportRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["module"].Value, fileIndex, imports);
            }
        }
    }

    private static void ParseJavaImport(string line, List<string> imports, ImportGraphFileIndex fileIndex)
    {
        if (!line.StartsWith("import ", StringComparison.Ordinal))
        {
            return;
        }

        var match = JavaImportRegex().Match(line);
        if (match.Success)
        {
            AddResolvedModule(match.Groups["pkg"].Value, fileIndex, imports);
        }
    }

    private static void ParseGoImport(string line, List<string> imports, ImportGraphFileIndex fileIndex)
    {
        var match = GoImportRegex().Match(line);
        if (match.Success)
        {
            AddResolvedModule(match.Groups["path"].Value, fileIndex, imports);
        }
    }

    private static void ParseRustImport(string line, List<string> imports, ImportGraphFileIndex fileIndex)
    {
        if (line.StartsWith("use ", StringComparison.Ordinal))
        {
            var match = RustUseRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["path"].Value.Replace("::", "/", StringComparison.Ordinal), fileIndex, imports);
            }
        }
        else if (line.StartsWith("mod ", StringComparison.Ordinal))
        {
            var match = RustModRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["name"].Value, fileIndex, imports);
            }
        }
    }

    private static string? ResolveRelativePath(string sourceRelativePath, string importPath, ImportGraphFileIndex fileIndex)
    {
        var sourceDir = Path.GetDirectoryName(sourceRelativePath)?.Replace('\\', '/') ?? string.Empty;
        var combined = string.IsNullOrEmpty(sourceDir)
            ? importPath
            : $"{sourceDir}/{importPath}";

        var parts = combined.Split('/');
        var stack = new Stack<string>();

        foreach (var part in parts)
        {
            if (part is "." or "")
            {
                continue;
            }

            if (part == "..")
            {
                if (stack.Count > 0)
                {
                    stack.Pop();
                }
            }
            else
            {
                stack.Push(part);
            }
        }

        return stack.Count == 0 ? null : ResolveCandidate(string.Join("/", stack.Reverse()), fileIndex);
    }

    private static void AddResolvedModule(string module, ImportGraphFileIndex fileIndex, List<string> imports)
    {
        var resolved = fileIndex.ResolveSuffixPath(module.Replace('.', '/').Trim('/'));
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static string? ResolveCandidate(string candidate, ImportGraphFileIndex fileIndex)
    {
        var normalized = candidate.Replace('\\', '/').TrimStart('/');
        if (fileIndex.Contains(normalized))
        {
            return normalized;
        }

        foreach (var extension in SourceExtensions)
        {
            var withExtension = normalized + extension;
            if (fileIndex.Contains(withExtension))
            {
                return withExtension;
            }

            var indexFile = $"{normalized}/index{extension}";
            if (fileIndex.Contains(indexFile))
            {
                return indexFile;
            }
        }

        return fileIndex.ResolveSuffixPath(normalized);
    }

    private sealed class ImportGraphFileIndex
    {
        private readonly HashSet<string> knownFiles;
        private readonly Dictionary<string, string?> uniqueSuffixes;

        public ImportGraphFileIndex(IEnumerable<string> files)
        {
            knownFiles = files.ToHashSet(StringComparer.OrdinalIgnoreCase);
            uniqueSuffixes = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            foreach (var file in knownFiles)
            {
                AddSuffixes(file);
            }
        }

        public bool Contains(string normalizedPath) => knownFiles.Contains(normalizedPath);

        public string? ResolveSuffixPath(string modulePath)
        {
            if (string.IsNullOrWhiteSpace(modulePath))
            {
                return null;
            }

            foreach (var extension in SourceExtensions)
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
    }

    [GeneratedRegex(@"^using\s+(?!var\b)(?!static\b)(?<ns>[A-Za-z_][\w.]*)\s*;", RegexOptions.None)]
    private static partial Regex CSharpUsingRegex();

    [GeneratedRegex(@"import\s+.*?\s+from\s+['""](?<path>[^'""]+)['""]", RegexOptions.None)]
    private static partial Regex JsImportFromRegex();

    [GeneratedRegex(@"^import\s*\{\s*(?:type\s+[A-Za-z_$][A-Za-z0-9_$]*\s*,?\s*)+\}\s+from\s+['""][^'""]+['""]", RegexOptions.None)]
    private static partial Regex JsTypeOnlyNamedImportRegex();

    [GeneratedRegex(@"import\s*\(\s*['""](?<path>[^'""]+)['""]\s*\)", RegexOptions.None)]
    private static partial Regex JsDynamicImportRegex();

    [GeneratedRegex(@"require\s*\(\s*['""](?<path>[^'""]+)['""]\s*\)", RegexOptions.None)]
    private static partial Regex JsRequireRegex();

    [GeneratedRegex(@"^from\s+(?<module>[A-Za-z_][\w.]*)\s+import\b", RegexOptions.None)]
    private static partial Regex PythonFromImportRegex();

    [GeneratedRegex(@"^import\s+(?<module>[A-Za-z_][\w.]*)", RegexOptions.None)]
    private static partial Regex PythonImportRegex();

    [GeneratedRegex(@"^import\s+(?:static\s+)?(?<pkg>[A-Za-z_][\w.]*)\s*;", RegexOptions.None)]
    private static partial Regex JavaImportRegex();

    [GeneratedRegex(@"""(?<path>[^""]+)""", RegexOptions.None)]
    private static partial Regex GoImportRegex();

    [GeneratedRegex(@"^use\s+(?<path>[A-Za-z_][\w:]*(?:::[A-Za-z_][\w:]*)*)", RegexOptions.None)]
    private static partial Regex RustUseRegex();

    [GeneratedRegex(@"^mod\s+(?<name>[A-Za-z_]\w*)\s*;", RegexOptions.None)]
    private static partial Regex RustModRegex();
}
