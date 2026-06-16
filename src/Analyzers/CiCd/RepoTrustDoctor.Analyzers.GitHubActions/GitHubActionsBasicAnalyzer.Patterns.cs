using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.GitHubActions;

public sealed partial class GitHubActionsBasicAnalyzer
{
    [GeneratedRegex(@"(?m)^\s*permissions\s*:")]
    private static partial Regex PermissionsPattern();

    [GeneratedRegex(@"(?mi)^\s*permissions\s*:\s*write-all\s*$")]
    private static partial Regex WriteAllPattern();

    [GeneratedRegex(@"(?mi)pull_request_target")]
    private static partial Regex PullRequestTargetPattern();

    [GeneratedRegex(@"(?mi)curl\b.+\|\s*(bash|sh)")]
    private static partial Regex CurlPipeShellPattern();

    [GeneratedRegex(@"(?mi)wget\b.+\|\s*(bash|sh)")]
    private static partial Regex WgetPipeShellPattern();

    [GeneratedRegex(@"uses\s*:\s*(?<action>[^@\s]+)@(?<version>[^\s#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex UsesPattern();

    [GeneratedRegex(@"^[a-f0-9]{40}$", RegexOptions.IgnoreCase)]
    private static partial Regex ShaPattern();

    [GeneratedRegex(@"(?mi)(?:^\s*runs-on\s*:\s*(?:['""]*self-hosted['""]*|\[[^\]]*\bself-hosted\b[^\]]*\])|^\s*-\s*['""]*self-hosted['""]*\s*$)")]
    private static partial Regex SelfHostedPattern();

    [GeneratedRegex(@"\buses\s*:\s*actions/checkout@", RegexOptions.IgnoreCase)]
    private static partial Regex UsesCheckoutPattern();

    [GeneratedRegex(@"\bpersist-credentials\s*:\s*['""]?false['""]?", RegexOptions.IgnoreCase)]
    private static partial Regex PersistCredentialsFalsePattern();

    [GeneratedRegex(@"^\s*(?:-\s*)?run\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex RunBlockPattern();

    [GeneratedRegex(@"\$\{\{\s*github\.(?:event\.|head_ref\b|ref_name\b)", RegexOptions.IgnoreCase)]
    private static partial Regex InjectionPattern();

    [GeneratedRegex(@"(?mi)\b(gh\s+release\s+(?:create|upload)|npm\s+publish|dotnet\s+nuget\s+push|nuget\s+push|twine\s+upload|docker\s+(?:push|buildx\s+build.+--push))\b")]
    private static partial Regex ReleasePublishPattern();

    [GeneratedRegex(@"\buses\s*:\s*actions/upload-artifact@", RegexOptions.IgnoreCase)]
    private static partial Regex UploadArtifactPattern();

    [GeneratedRegex(@"(?mi)^\s*path\s*:\s*(?<path>['""]?(?:\.|\.\/|\*\*\/\*)['""]?)\s*$")]
    private static partial Regex BroadArtifactPathPattern();

    [GeneratedRegex(@"(?mi)^\s*(?<key>TOKEN|PASSWORD|SECRET|API_KEY|AUTH_TOKEN)\s*:\s*(?<value>[^\s#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex HardcodedSecretEnvPattern();

    [GeneratedRegex(@"\$\{\{\s*matrix\.", RegexOptions.IgnoreCase)]
    private static partial Regex MatrixInjectionPattern();

    [GeneratedRegex(@"(?mi)^\s*(?<scope>[a-z0-9_-]+)\s*:\s*write\s*$")]
    private static partial Regex PermissionWriteValuePattern();

    [GeneratedRegex(@"(?mi)^\s*(?:contents|packages|actions|pull-requests|issues|checks|deployments)\s*:\s*write\s*$")]
    private static partial Regex WorkflowWritePermPattern();

    [GeneratedRegex(@"\buses\s*:\s*actions/cache@[\s\S]{0,200}path\s*:\s*(?<path>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex CacheBroadPathPattern();

    [GeneratedRegex(@"(?mi)^\s*image\s*:\s*(?<image>[^\s\n]+)", RegexOptions.IgnoreCase)]
    private static partial Regex JobContainerImagePattern();
}

