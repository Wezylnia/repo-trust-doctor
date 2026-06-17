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
        if (AspNetMethodRegex().Match(snippet) is { Success: true } aspNet)
        {
            return NormalizeHttpMethod(aspNet.Groups["method"].Value);
        }

        if (ExpressMethodRegex().Match(snippet) is { Success: true } express)
        {
            return NormalizeHttpMethod(express.Groups["method"].Value);
        }

        if (SpringMappingMethodRegex().Match(snippet) is { Success: true } springMapping)
        {
            return NormalizeHttpMethod(springMapping.Groups["method"].Value);
        }

        if (SpringRequestMethodRegex().Match(snippet) is { Success: true } springRequest)
        {
            return NormalizeHttpMethod(springRequest.Groups["method"].Value);
        }

        if (PythonRouteMethodsRegex().Match(snippet) is { Success: true } pythonMethods)
        {
            return NormalizeHttpMethod(pythonMethods.Groups["method"].Value);
        }

        if (GoMethodRegex().Match(snippet) is { Success: true } go)
        {
            return NormalizeHttpMethod(go.Groups["method"].Value);
        }

        if (RustMethodRegex().Match(snippet) is { Success: true } rust)
        {
            return NormalizeHttpMethod(rust.Groups["method"].Value);
        }

        return "GET";
    }

    private static string NormalizeHttpMethod(string method) =>
        method.ToUpperInvariant() switch
        {
            "GET" => "GET",
            "POST" => "POST",
            "PUT" => "PUT",
            "DELETE" => "DELETE",
            "PATCH" => "PATCH",
            "ALL" or "ANY" or "HANDLE" => "ANY",
            _ => "GET"
        };

    private static string? DeterminePathPattern(string snippet, string framework)
    {
        var match = PathLiteralRegex().Match(snippet);
        return match.Success ? match.Groups["path"].Value : null;
    }

    [GeneratedRegex(@"['""](?<path>[^'""]+)['""]")]
    private static partial Regex PathLiteralRegex();

    [GeneratedRegex(@"\b(?:Map|Http)(?<method>Get|Post|Put|Delete|Patch)\b", RegexOptions.IgnoreCase)]
    private static partial Regex AspNetMethodRegex();

    [GeneratedRegex(@"\.\s*(?<method>get|post|put|delete|patch|all)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex ExpressMethodRegex();

    [GeneratedRegex(@"@\s*(?<method>Get|Post|Put|Delete|Patch)Mapping\b", RegexOptions.IgnoreCase)]
    private static partial Regex SpringMappingMethodRegex();

    [GeneratedRegex(@"RequestMethod\s*\.\s*(?<method>GET|POST|PUT|DELETE|PATCH)", RegexOptions.IgnoreCase)]
    private static partial Regex SpringRequestMethodRegex();

    [GeneratedRegex(@"methods\s*=\s*\[[^\]]*['""](?<method>GET|POST|PUT|DELETE|PATCH)['""]", RegexOptions.IgnoreCase)]
    private static partial Regex PythonRouteMethodsRegex();

    [GeneratedRegex(@"\.\s*(?<method>GET|POST|PUT|DELETE|PATCH|Handle|Any)\s*\(")]
    private static partial Regex GoMethodRegex();

    [GeneratedRegex(@"(?:web::|#\[\s*)(?<method>get|post|put|delete|patch)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex RustMethodRegex();
}

