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

        if (extension == ".go")
        {
            ParseGoImports(text, imports, fileIndex);
            return imports
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();

            switch (extension)
            {
                case ".ts" or ".tsx" or ".js" or ".jsx":
                    ParseJavaScriptImport(trimmed, imports, sourceRelativePath, fileIndex);
                    break;
                case ".py":
                    ParsePythonImport(trimmed, imports, fileIndex);
                    break;
                case ".java":
                    ParseJavaImport(trimmed, imports, fileIndex);
                    break;
                case ".rs":
                    ParseRustImport(trimmed, imports, fileIndex);
                    break;
            }
        }

        return imports
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
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

    private static void ParseGoImports(
        string text,
        ICollection<string> imports,
        ImportGraphFileIndex fileIndex)
    {
        var inImportBlock = false;
        foreach (var rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripGoLineComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (inImportBlock)
            {
                if (line.StartsWith(')'))
                {
                    inImportBlock = false;
                    continue;
                }

                AddResolvedGoImport(line, imports, fileIndex);
                continue;
            }

            if (!line.StartsWith("import", StringComparison.Ordinal) ||
                line.Length <= "import".Length ||
                !char.IsWhiteSpace(line["import".Length]))
            {
                continue;
            }

            var importSpec = line["import".Length..].Trim();
            if (importSpec == "(")
            {
                inImportBlock = true;
            }
            else
            {
                AddResolvedGoImport(importSpec, imports, fileIndex);
            }
        }
    }

    private static void AddResolvedGoImport(
        string importSpec,
        ICollection<string> imports,
        ImportGraphFileIndex fileIndex)
    {
        var match = GoImportSpecRegex().Match(importSpec);
        if (!match.Success)
        {
            return;
        }

        var resolved = fileIndex.ResolveGoPackage(match.Groups["path"].Value);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static string StripGoLineComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length - 1; index++)
        {
            var current = line[index];
            if (quote == '\0' && current is '"' or '`')
            {
                quote = current;
            }
            else if (quote == current && (quote == '`' || index == 0 || line[index - 1] != '\\'))
            {
                quote = '\0';
            }
            else if (quote == '\0' && current == '/' && line[index + 1] == '/')
            {
                return line[..index];
            }
        }

        return line;
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

    [GeneratedRegex(@"^(?:(?:[._A-Za-z][A-Za-z0-9_]*)\s+)?[""`](?<path>[^""`]+)[""`]\s*$", RegexOptions.None)]
    private static partial Regex GoImportSpecRegex();

    [GeneratedRegex(@"^use\s+(?<path>[A-Za-z_][\w:]*(?:::[A-Za-z_][\w:]*)*)", RegexOptions.None)]
    private static partial Regex RustUseRegex();

    [GeneratedRegex(@"^mod\s+(?<name>[A-Za-z_]\w*)\s*;", RegexOptions.None)]
    private static partial Regex RustModRegex();

}
