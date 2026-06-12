using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class ImportGraphAnalyzer
{
    private static List<string> ParseImports(
        string text,
        string extension,
        string sourceRelativePath,
        IReadOnlySet<string> knownFiles)
    {
        var imports = new List<string>();

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();

            switch (extension)
            {
                case ".cs":
                    ParseCSharpImport(trimmed, imports, knownFiles);
                    break;
                case ".ts" or ".tsx" or ".js" or ".jsx":
                    ParseJavaScriptImport(trimmed, imports, sourceRelativePath, knownFiles);
                    break;
                case ".py":
                    ParsePythonImport(trimmed, imports, knownFiles);
                    break;
                case ".java":
                    ParseJavaImport(trimmed, imports, knownFiles);
                    break;
                case ".go":
                    ParseGoImport(trimmed, imports, knownFiles);
                    break;
                case ".rs":
                    ParseRustImport(trimmed, imports, knownFiles);
                    break;
            }
        }

        return imports;
    }

    private static void ParseCSharpImport(string line, List<string> imports, IReadOnlySet<string> knownFiles)
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

        var resolved = ResolveSuffixPath(ns.Replace('.', '/'), knownFiles);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static void ParseJavaScriptImport(string line, List<string> imports, string sourceRelativePath, IReadOnlySet<string> knownFiles)
    {
        Match? match = null;

        if (line.StartsWith("import", StringComparison.Ordinal))
        {
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

        var resolved = ResolveRelativePath(sourceRelativePath, path, knownFiles);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static void ParsePythonImport(string line, List<string> imports, IReadOnlySet<string> knownFiles)
    {
        if (line.StartsWith("from ", StringComparison.Ordinal))
        {
            var match = PythonFromImportRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["module"].Value, knownFiles, imports);
            }
        }
        else if (line.StartsWith("import ", StringComparison.Ordinal))
        {
            var match = PythonImportRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["module"].Value, knownFiles, imports);
            }
        }
    }

    private static void ParseJavaImport(string line, List<string> imports, IReadOnlySet<string> knownFiles)
    {
        if (!line.StartsWith("import ", StringComparison.Ordinal))
        {
            return;
        }

        var match = JavaImportRegex().Match(line);
        if (match.Success)
        {
            AddResolvedModule(match.Groups["pkg"].Value, knownFiles, imports);
        }
    }

    private static void ParseGoImport(string line, List<string> imports, IReadOnlySet<string> knownFiles)
    {
        var match = GoImportRegex().Match(line);
        if (match.Success)
        {
            AddResolvedModule(match.Groups["path"].Value, knownFiles, imports);
        }
    }

    private static void ParseRustImport(string line, List<string> imports, IReadOnlySet<string> knownFiles)
    {
        if (line.StartsWith("use ", StringComparison.Ordinal))
        {
            var match = RustUseRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["path"].Value.Replace("::", "/", StringComparison.Ordinal), knownFiles, imports);
            }
        }
        else if (line.StartsWith("mod ", StringComparison.Ordinal))
        {
            var match = RustModRegex().Match(line);
            if (match.Success)
            {
                AddResolvedModule(match.Groups["name"].Value, knownFiles, imports);
            }
        }
    }

    private static string? ResolveRelativePath(string sourceRelativePath, string importPath, IReadOnlySet<string> knownFiles)
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

        return stack.Count == 0 ? null : ResolveCandidate(string.Join("/", stack.Reverse()), knownFiles);
    }

    private static void AddResolvedModule(string module, IReadOnlySet<string> knownFiles, List<string> imports)
    {
        var resolved = ResolveSuffixPath(module.Replace('.', '/').Trim('/'), knownFiles);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static string? ResolveCandidate(string candidate, IReadOnlySet<string> knownFiles)
    {
        var normalized = candidate.Replace('\\', '/').TrimStart('/');
        if (knownFiles.Contains(normalized))
        {
            return normalized;
        }

        foreach (var extension in SourceExtensions)
        {
            var withExtension = normalized + extension;
            if (knownFiles.Contains(withExtension))
            {
                return withExtension;
            }

            var indexFile = $"{normalized}/index{extension}";
            if (knownFiles.Contains(indexFile))
            {
                return indexFile;
            }
        }

        return ResolveSuffixPath(normalized, knownFiles);
    }

    private static string? ResolveSuffixPath(string modulePath, IReadOnlySet<string> knownFiles)
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
            var matches = knownFiles
                .Where(file => file.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
                               file.EndsWith('/' + suffix, StringComparison.OrdinalIgnoreCase))
                .Take(2)
                .ToArray();
            if (matches.Length == 1)
            {
                return matches[0];
            }
        }

        return null;
    }

    [GeneratedRegex(@"^using\s+(?!var\b)(?!static\b)(?<ns>[A-Za-z_][\w.]*)\s*;", RegexOptions.None)]
    private static partial Regex CSharpUsingRegex();

    [GeneratedRegex(@"import\s+.*?\s+from\s+['""](?<path>[^'""]+)['""]", RegexOptions.None)]
    private static partial Regex JsImportFromRegex();

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
