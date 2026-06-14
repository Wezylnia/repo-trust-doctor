using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class FrameworkRouteAnalyzer
{
    [GeneratedRegex(
        @"\[\s*(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\s*(?:\(.*?\))?\s*\]|app\.(?:MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex AspNetRouteRegex();

    [GeneratedRegex(
        @"\[\s*(?:Authorize|AllowAnonymous)\s*(?:\(.*?\))?\s*\]|(?:RequireAuthorization|AllowAnonymous)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex AspNetAuthRegex();

    [GeneratedRegex(
        @"(?:app|router)\s*\.\s*(?:(?:get|post|put|delete|patch|all)\s*\(|use\s*\((?=\s*['""]))",
        RegexOptions.IgnoreCase)]
    private static partial Regex ExpressRouteRegex();

    [GeneratedRegex(
        @"passport|authenticate|authMiddleware|(?:^|[.\s(,])auth(?:[.\s),]|$)|jwt|isAuthenticated|requireAuth",
        RegexOptions.IgnoreCase)]
    private static partial Regex ExpressAuthRegex();

    [GeneratedRegex(
        @"@\s*(?:app|bp|blueprint)\s*\.\s*route\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex FlaskRouteRegex();

    [GeneratedRegex(
        @"@login_required|@auth_required|@requires_auth|flask_login",
        RegexOptions.IgnoreCase)]
    private static partial Regex FlaskAuthRegex();

    [GeneratedRegex(
        @"(?m)^\s*(?:path|re_path|url)\s*\(")]
    private static partial Regex DjangoRouteRegex();

    [GeneratedRegex(
        @"@login_required|LoginRequiredMixin|@permission_required|staff_member_required|user_passes_test|admin_view",
        RegexOptions.IgnoreCase)]
    private static partial Regex DjangoAuthRegex();

    [GeneratedRegex(
        @"@\s*(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(.*?\))?",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex SpringRouteRegex();

    [GeneratedRegex(
        @"@\s*(?:PreAuthorize|Secured|RolesAllowed)\b|hasRole|hasAuthority",
        RegexOptions.IgnoreCase)]
    private static partial Regex SpringAuthRegex();

    [GeneratedRegex(
        @"(?:r|router|e|g|group)\s*\.\s*(?:GET|POST|PUT|DELETE|PATCH|Handle|Any)\s*\(",
        RegexOptions.None)]
    private static partial Regex GoRouteRegex();

    [GeneratedRegex(
        @"AuthMiddleware|JWTMiddleware|authRequired|AuthRequired",
        RegexOptions.None)]
    private static partial Regex GoAuthRegex();

    [GeneratedRegex(
        @"web::(?:get|post|put|delete|patch|resource)\s*\(|\.route\s*\(|Router::new\s*\(|#\[\s*(?:get|post|put|delete|patch)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex RustRouteRegex();

    [GeneratedRegex(
        @"auth|AuthMiddleware|jwt|Claims",
        RegexOptions.IgnoreCase)]
    private static partial Regex RustAuthRegex();

    private sealed record FrameworkDefinition(
        string Name,
        IReadOnlyList<string> Extensions,
        Regex RoutePattern,
        Regex AuthPattern);

    private sealed record FrameworkRouteInfo(
        string FilePath,
        string Framework,
        string Snippet,
        int LineNumber,
        bool HasAuthHint);

    private static string DetermineHttpMethod(string snippet, string framework)
    {
        var lower = snippet.ToLowerInvariant();
        if (lower.Contains("get")) return "GET";
        if (lower.Contains("post")) return "POST";
        if (lower.Contains("put")) return "PUT";
        if (lower.Contains("delete")) return "DELETE";
        if (lower.Contains("patch")) return "PATCH";
        return "GET";
    }

    private static string? DeterminePathPattern(string snippet, string framework)
    {
        var match = PathLiteralRegex().Match(snippet);
        return match.Success ? match.Groups["path"].Value : null;
    }

    [GeneratedRegex(@"['""](?<path>[^'""]+)['""]")]
    private static partial Regex PathLiteralRegex();

}

