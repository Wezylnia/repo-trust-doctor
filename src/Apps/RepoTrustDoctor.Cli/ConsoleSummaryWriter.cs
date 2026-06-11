using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Shared;

internal static class ConsoleSummaryWriter
{
    public static string Build(RepositoryScan scan)
    {
        var summary = scan.Summary;
        var lines = new List<string>
        {
            ProductInfo.Name,
            $"Version: {scan.ToolVersion}",
            $"Target: {scan.Target}",
            $"Depth: {scan.Depth}",
            $"Trust profile: {scan.TrustProfile}",
            $"Score: {scan.Score.Overall}/100",
            $"Decision: {scan.Score.Decision.Kind}",
            $"Findings: {scan.Findings.Count}",
            $"Severity summary: Critical={summary.Critical}, High={summary.High}, Medium={summary.Medium}, Low={summary.Low}, Info={summary.Info}",
            string.Empty,
            "Category scores:"
        };

        foreach (var category in scan.Score.Categories.OrderByDescending(category => category.Score))
        {
            lines.Add($"  {category.Category,-22} {category.Score,3}/100 {ScoreBar(category.Score)}");
        }

        lines.Add(string.Empty);
        lines.Add("Top findings:");
        lines.AddRange(scan.Findings
            .OrderByDescending(finding => finding.Severity)
            .Take(10)
            .Select(finding => $"- [{finding.Severity}] {finding.RuleId}: {finding.Title}"));

        if (scan.Findings.Count == 0)
        {
            lines.Add("- none");
        }

        AppendDependencySummary(lines, scan);
        AppendTopActions(lines, scan);
        return string.Join(Environment.NewLine, lines);
    }

    private static void AppendDependencySummary(List<string> lines, RepositoryScan scan)
    {
        if (scan.Artifacts?.TryGetValue(DependencyInventoryArtifact.ArtifactKey, out var artifact) != true ||
            artifact is not DependencyInventoryArtifact inventory)
        {
            return;
        }

        lines.Add(string.Empty);
        lines.Add($"Dependencies: {inventory.Packages.Count} packages across {inventory.Manifests.Count} manifests");
        lines.Add($"  Unpinned: {inventory.Packages.Count(package => !package.IsVersionPinned)}, Prerelease: {inventory.Packages.Count(package => package.IsPrerelease)}");
    }

    private static void AppendTopActions(List<string> lines, RepositoryScan scan)
    {
        var actions = scan.Findings
            .Select(finding => finding.Recommendation.Message)
            .Where(message => !string.IsNullOrWhiteSpace(message))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .ToArray();

        if (actions.Length == 0)
        {
            return;
        }

        lines.Add(string.Empty);
        lines.Add("Top actions:");
        foreach (var action in actions)
        {
            lines.Add($"  - {action}");
        }
    }

    private static string ScoreBar(int score) => score switch
    {
        >= 90 => "++++++++++",
        >= 80 => "++++++++  ",
        >= 70 => "+++++++   ",
        >= 60 => "++++++    ",
        >= 50 => "+++++     ",
        >= 40 => "++++      ",
        >= 30 => "+++       ",
        >= 20 => "++        ",
        _ => "+         "
    };
}
