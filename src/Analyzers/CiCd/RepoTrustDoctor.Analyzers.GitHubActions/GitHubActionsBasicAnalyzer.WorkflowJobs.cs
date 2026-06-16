using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.GitHubActions;

public sealed partial class GitHubActionsBasicAnalyzer
{
    private static IReadOnlyList<WorkflowJob> ParseWorkflowJobs(string content)
    {
        var lines = SplitLines(content);
        var jobsLine = Array.FindIndex(lines, line =>
            GetIndentation(line) == 0 &&
            line.TrimStart().StartsWith("jobs:", StringComparison.OrdinalIgnoreCase));
        if (jobsLine < 0)
        {
            return [];
        }

        var jobs = new List<WorkflowJob>();
        for (var index = jobsLine + 1; index < lines.Length; index++)
        {
            var line = lines[index];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (GetIndentation(line) == 0)
            {
                break;
            }

            var match = Regex.Match(line, @"^\s{2}(?<name>[A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$");
            if (!match.Success)
            {
                continue;
            }

            var start = index;
            var end = lines.Length;
            for (var cursor = index + 1; cursor < lines.Length; cursor++)
            {
                if (!string.IsNullOrWhiteSpace(lines[cursor]) &&
                    GetIndentation(lines[cursor]) <= 2)
                {
                    end = cursor;
                    break;
                }
            }

            var body = string.Join('\n', lines.Skip(start).Take(end - start));
            jobs.Add(new WorkflowJob(match.Groups["name"].Value, body, ParseNeeds(body)));
            index = end - 1;
        }

        return jobs;
    }

    private static IReadOnlyList<string> ParseNeeds(string jobBody)
    {
        var lines = SplitLines(jobBody);
        for (var index = 0; index < lines.Length; index++)
        {
            var match = Regex.Match(lines[index], @"^\s*needs\s*:\s*(?<value>.*?)\s*(?:#.*)?$", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var value = match.Groups["value"].Value.Trim();
            if (value.StartsWith('['))
            {
                return value.Trim('[', ']')
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(item => item.Trim('"', '\''))
                    .Where(item => item.Length > 0)
                    .ToArray();
            }

            if (!string.IsNullOrWhiteSpace(value))
            {
                return [value.Trim('"', '\'')];
            }

            return ParseNeedsBlock(lines, index);
        }

        return [];
    }

    private static IReadOnlyList<string> ParseNeedsBlock(string[] lines, int headerIndex)
    {
        var baseIndent = GetIndentation(lines[headerIndex]);
        var needs = new List<string>();
        for (var cursor = headerIndex + 1; cursor < lines.Length; cursor++)
        {
            var child = lines[cursor];
            if (string.IsNullOrWhiteSpace(child))
            {
                continue;
            }

            if (GetIndentation(child) <= baseIndent)
            {
                break;
            }

            var itemMatch = Regex.Match(child, @"^\s*-\s*(?<name>[A-Za-z0-9_.-]+)\s*(?:#.*)?$");
            if (itemMatch.Success)
            {
                needs.Add(itemMatch.Groups["name"].Value);
            }
        }

        return needs;
    }

    private static bool JobTransitivelyNeedsValidation(
        WorkflowJob job,
        IReadOnlyDictionary<string, WorkflowJob> jobs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>(job.Needs);
        while (stack.Count > 0)
        {
            var dependency = stack.Pop();
            if (!seen.Add(dependency))
            {
                continue;
            }

            if (IsValidationJobName(dependency) &&
                (!jobs.TryGetValue(dependency, out var validationJob) ||
                 !JobAllowsValidationFailure(validationJob)))
            {
                return true;
            }

            if (jobs.TryGetValue(dependency, out var dependencyJob))
            {
                foreach (var nested in dependencyJob.Needs)
                {
                    stack.Push(nested);
                }
            }
        }

        return false;
    }

    private static bool IsValidationJobName(string name) =>
        name.Contains("test", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("ci", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("build-and-test", StringComparison.OrdinalIgnoreCase);

    private static bool JobAllowsValidationFailure(WorkflowJob job) =>
        Regex.IsMatch(job.Body, @"(?mi)^\s*continue-on-error\s*:\s*true\s*(?:#.*)?$");

    private static bool JobRunsRegardlessOfNeedsResult(WorkflowJob job) =>
        Regex.IsMatch(job.Body, @"(?mi)^\s*if\s*:\s*(?:\$\{\{\s*)?always\s*\(\s*\)\s*(?:\}\})?\s*(?:#.*)?$");

    private sealed record WorkflowJob(string Name, string Body, IReadOnlyList<string> Needs);
}
