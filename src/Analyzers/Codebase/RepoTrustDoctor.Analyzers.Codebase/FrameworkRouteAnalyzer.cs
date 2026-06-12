using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class FrameworkRouteAnalyzer : IRepositoryAnalyzer
{
    private const int UnauthFindingLimit = 15;
    private const int RouteFindingLimit = 20;

    private static readonly IReadOnlyList<FrameworkDefinition> Frameworks =
    [
        new(
            "ASP.NET",
            [".cs"],
            AspNetRouteRegex(),
            AspNetAuthRegex()),
        new(
            "Express.js",
            [".js", ".ts"],
            ExpressRouteRegex(),
            ExpressAuthRegex()),
        new(
            "Flask",
            [".py"],
            FlaskRouteRegex(),
            FlaskAuthRegex()),
        new(
            "Django",
            [".py"],
            DjangoRouteRegex(),
            DjangoAuthRegex()),
        new(
            "Spring Boot",
            [".java", ".kt"],
            SpringRouteRegex(),
            SpringAuthRegex()),
        new(
            "Go Gin/Echo",
            [".go"],
            GoRouteRegex(),
            GoAuthRegex()),
        new(
            "Rust Actix/Axum",
            [".rs"],
            RustRouteRegex(),
            RustAuthRegex())
    ];

    public string Id => "codebase-06-framework-routes";

    public string DisplayName => "Framework Route Detection";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(20);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE012",
            "HTTP endpoint without authentication annotation",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Low,
            "An HTTP route handler was detected without a visible authentication or authorization annotation.",
            "Add authentication middleware or [Authorize] annotations to HTTP endpoints, or document why public access is intentional."),
        new(
            "TRUST-CODE013",
            "Framework route detected",
            AnalysisCategory.Codebase,
            Severity.Info,
            Confidence.High,
            "An HTTP route or controller endpoint was detected using a common web framework.",
            "Review HTTP endpoints for proper authentication, authorization, input validation, and rate limiting.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var detectedRoutes = new List<FrameworkRouteInfo>();

        foreach (var file in EnumerateSourceFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var extension = Path.GetExtension(file);
            var matchingFrameworks = GetMatchingFrameworks(extension);
            if (matchingFrameworks.Count == 0)
            {
                continue;
            }

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

            foreach (var framework in matchingFrameworks)
            {
                var routeMatches = framework.RoutePattern.Matches(text);
                if (routeMatches.Count == 0)
                {
                    continue;
                }

                var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

                foreach (Match routeMatch in routeMatches)
                {
                    var lineNumber = CountLineNumber(text, routeMatch.Index);
                    var snippet = ExtractRouteSnippet(text, routeMatch);
                    var hasAuth = HasAuthNearRoute(framework, lines, lineNumber, text, routeMatch);

                    detectedRoutes.Add(new FrameworkRouteInfo(
                        relativePath,
                        framework.Name,
                        snippet,
                        lineNumber,
                        hasAuth));
                }
            }
        }

        var ordered = detectedRoutes
            .OrderBy(route => route.HasAuthHint)
            .ThenBy(route => route.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(route => route.LineNumber)
            .ToArray();

        var findings = new List<Finding>();

        // TRUST-CODE012: unauthenticated endpoints
        findings.AddRange(ordered
            .Where(route => !route.HasAuthHint)
            .Take(UnauthFindingLimit)
            .Select(route => new Finding(
                "TRUST-CODE012",
                "HTTP endpoint without authentication annotation",
                AnalysisCategory.Codebase,
                Severity.Medium,
                Confidence.Low,
                $"{route.FilePath}:{route.LineNumber.ToString(CultureInfo.InvariantCulture)} - {route.Framework} route \"{Truncate(route.Snippet, 80)}\" has no visible auth annotation near the route.",
                [new Evidence(
                    "route.no_auth",
                    $"No authentication or authorization annotation found near {route.Framework} route.",
                    route.FilePath,
                    route.LineNumber,
                    route.Snippet)],
                new Recommendation("Add authentication middleware or [Authorize] annotations to HTTP endpoints, or document why public access is intentional."),
                Tags: ["codebase", "routes", "auth"])));

        // TRUST-CODE013: informational route detection
        findings.AddRange(ordered
            .Take(RouteFindingLimit)
            .Select(route => new Finding(
                "TRUST-CODE013",
                "Framework route detected",
                AnalysisCategory.Codebase,
                Severity.Info,
                Confidence.High,
                $"{route.FilePath}:{route.LineNumber.ToString(CultureInfo.InvariantCulture)} - {route.Framework} route \"{Truncate(route.Snippet, 80)}\" detected.",
                [new Evidence(
                    "route.detected",
                    $"{route.Framework} HTTP route detected.",
                    route.FilePath,
                    route.LineNumber,
                    route.Snippet)],
                new Recommendation("Review HTTP endpoints for proper authentication, authorization, input validation, and rate limiting."),
                Tags: ["codebase", "routes"])));

        var unauthCount = ordered.Count(route => !route.HasAuthHint);
        var frameworkCounts = ordered
            .GroupBy(route => route.Framework, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);

        var metrics = new Dictionary<string, string>
        {
            ["route.total.count"] = ordered.Length.ToString(CultureInfo.InvariantCulture),
            ["route.unauthenticated.count"] = unauthCount.ToString(CultureInfo.InvariantCulture),
            ["route.frameworks"] = string.Join(", ", frameworkCounts.Select(
                kvp => $"{kvp.Key}={kvp.Value.ToString(CultureInfo.InvariantCulture)}"))
        };

        var routeEntries = ordered
            .Select(r => new RouteEntry(
                DetermineHttpMethod(r.Snippet, r.Framework),
                DeterminePathPattern(r.Snippet, r.Framework),
                r.Framework,
                r.FilePath,
                r.LineNumber,
                r.HasAuthHint))
            .ToArray();

        var artifact = new FrameworkRouteArtifact(routeEntries, metrics);

        return AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(FrameworkRouteArtifact.ArtifactKey, artifact)],
            metrics);
    }

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => !IsTestSource(root, file))
            .Where(file =>
            {
                var ext = Path.GetExtension(file);
                return Frameworks.Any(fw => fw.Extensions.Contains(ext, StringComparer.OrdinalIgnoreCase));
            });

    private static List<FrameworkDefinition> GetMatchingFrameworks(string extension) =>
        Frameworks
            .Where(fw => fw.Extensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
            .ToList();

    private static int CountLineNumber(string text, int charIndex)
    {
        var line = 1;
        for (var i = 0; i < charIndex && i < text.Length; i++)
        {
            if (text[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : string.Concat(value.AsSpan(0, maxLength - 3), "...");

    private static string ExtractRouteSnippet(string text, Match routeMatch)
    {
        var value = routeMatch.Value.Trim();
        return value.EndsWith('(')
            ? GetRouteStatement(text, routeMatch).Trim()
            : value;
    }

    private static bool HasAuthNearRoute(
        FrameworkDefinition framework,
        string[] lines,
        int lineNumber,
        string text,
        Match routeMatch)
    {
        var routeIndex = Math.Clamp(lineNumber - 1, 0, Math.Max(0, lines.Length - 1));

        if (framework.Name == "ASP.NET")
        {
            var start = Math.Max(0, routeIndex - 4);
            var end = Math.Min(lines.Length - 1, routeIndex + 4);
            var nearby = string.Join('\n', lines[start..(end + 1)]);
            if (framework.AuthPattern.IsMatch(nearby))
            {
                return true;
            }

            return HasAspNetClassAuthorize(lines, routeIndex) ||
                   HasAspNetAuthInChainedCall(text, routeMatch);
        }

        if (framework.Name is "Express.js" or "Go Gin/Echo" or "Rust Actix/Axum")
        {
            return framework.AuthPattern.IsMatch(GetRouteStatement(text, routeMatch));
        }

        var contextStart = Math.Max(0, routeIndex - 2);
        var contextEnd = Math.Min(lines.Length - 1, routeIndex + 2);
        var routeContext = string.Join('\n', lines[contextStart..(contextEnd + 1)]);
        if (framework.AuthPattern.IsMatch(routeContext))
        {
            return true;
        }

        return false;
    }

    private static bool HasAspNetClassAuthorize(string[] lines, int routeIndex)
    {
        for (var i = Math.Min(routeIndex, lines.Length - 1); i >= 0; i--)
        {
            if (!lines[i].Contains("class ", StringComparison.Ordinal))
            {
                continue;
            }

            var start = Math.Max(0, i - 6);
            var classHeader = string.Join('\n', lines[start..(i + 1)]);
            return AspNetAuthRegex().IsMatch(classHeader);
        }

        return false;
    }

    private static bool HasAspNetAuthInChainedCall(string text, Match routeMatch)
    {
        var statement = GetRouteStatement(text, routeMatch);
        return statement.Contains("RequireAuthorization", StringComparison.OrdinalIgnoreCase) ||
               statement.Contains("AllowAnonymous", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTestSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        var fileName = Path.GetFileNameWithoutExtension(relativePath);
        return relativePath.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith("Tests", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith("Test", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".spec", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".test", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetRouteStatement(string text, Match routeMatch)
    {
        var end = text.IndexOf(';', routeMatch.Index);
        var newline = text.IndexOf('\n', routeMatch.Index);
        if (end < 0 || (newline >= 0 && newline < end))
        {
            end = newline >= 0 ? newline : Math.Min(text.Length, routeMatch.Index + 300);
        }

        var length = Math.Min(end - routeMatch.Index + 1, text.Length - routeMatch.Index);
        return length <= 0 ? string.Empty : text.Substring(routeMatch.Index, length);
    }

}

