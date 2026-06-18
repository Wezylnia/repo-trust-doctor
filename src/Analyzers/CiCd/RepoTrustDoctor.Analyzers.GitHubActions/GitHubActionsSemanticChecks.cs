using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.GitHubActions;

internal static class GitHubActionsSemanticChecks
{
    private static readonly string[] ValidationJobNameHints =
        ["test", "security", "scan", "lint", "validate", "verification", "audit"];
    private static readonly string[] OptionalValidationHints =
        ["experimental", "compat", "compatibility", "optional"];
    private static readonly string[] NotificationStepHints =
        ["notify", "notification", "slack", "teams", "discord"];

    public static IReadOnlyList<Finding> RunAll(
        string content,
        string relativePath,
        GitHubWorkflowModel model)
    {
        var findings = new List<Finding>();

        CheckMutableReusableWorkflow(content, relativePath, model, findings);
        CheckValidationJobContinueOnError(relativePath, model, findings);
        CheckReleaseJobUnconditional(relativePath, model, findings);
        CheckUntrustedEventInCacheKey(content, relativePath, findings);
        CheckReleaseWithoutTestDependency(relativePath, model, findings);
        CheckWorkflowWritePermissions(content, relativePath, model, findings);

        return findings;
    }

    // TRUST-GHA019: Mutable reusable workflow reference
    private static void CheckMutableReusableWorkflow(
        string content,
        string relativePath,
        GitHubWorkflowModel model,
        List<Finding> findings)
    {
        foreach (var job in model.Jobs.Values)
        {
            if (job.Uses is not null)
            {
                CheckReusableWorkflowReference(relativePath, findings, job.Uses, job.StartLine, job.Name);
            }

            foreach (var step in job.Steps)
            {
                if (step.Uses is not null)
                {
                    CheckReusableWorkflowReference(relativePath, findings, step.Uses, step.StartLine, job.Name);
                }
            }
        }
    }

    // TRUST-GHA020: Validation job is allowed to fail
    private static void CheckValidationJobContinueOnError(
        string relativePath,
        GitHubWorkflowModel model,
        List<Finding> findings)
    {
        foreach (var job in model.Jobs.Values)
        {
            if (job.ContinueOnError &&
                IsValidationName(job.Name) &&
                !IsOptionalValidationName(job.Name))
            {
                AddFinding(
                    findings,
                    "TRUST-GHA020",
                    "Validation job is allowed to fail",
                    Severity.Medium,
                    "Remove continue-on-error from validation jobs to ensure failures are visible.",
                    relativePath,
                    $"Validation job '{job.Name}' has continue-on-error: true.",
                    job.StartLine,
                    Confidence.High,
                    identityKey: $"gha020|{relativePath}|job|{job.Name}");
            }

            foreach (var step in job.Steps)
            {
                if (step.ContinueOnError &&
                    step.Name is not null &&
                    IsValidationName(step.Name) &&
                    !IsOptionalValidationName(step.Name) &&
                    !IsNotificationStepName(step.Name))
                {
                    AddFinding(
                        findings,
                        "TRUST-GHA020",
                    "Validation step is allowed to fail",
                    Severity.Medium,
                    "Remove continue-on-error from validation steps to ensure failures are visible.",
                    relativePath,
                    $"Validation step '{step.Name}' in job '{job.Name}' has continue-on-error: true.",
                    step.StartLine,
                    Confidence.High,
                    identityKey: $"gha020|{relativePath}|step|{job.Name}|{step.Name}");
                }
            }
        }
    }

    // TRUST-GHA021: Release job runs regardless of failed dependencies
    private static void CheckReleaseJobUnconditional(
        string relativePath,
        GitHubWorkflowModel model,
        List<Finding> findings)
    {
        var jobsByName = model.Jobs;

        foreach (var job in jobsByName.Values)
        {
            if (!IsPublishOrReleaseJob(job))
            {
                continue;
            }

            if (job.IfExpression is not null &&
                job.IfExpression.Contains("always()", StringComparison.OrdinalIgnoreCase))
            {
                if (HasStrictValidationDependency(job, jobsByName))
                {
                    AddFinding(
                        findings,
                        "TRUST-GHA021",
                        "Release job runs regardless of failed dependencies",
                        Severity.High,
                        "Avoid if: always() on release jobs that depend on validation. Only publish after successful validation.",
                        relativePath,
                        $"Release job '{job.Name}' uses if: always() and depends on validation jobs. It may publish after a failed dependency.",
                        job.StartLine,
                        Confidence.Medium,
                        identityKey: $"gha021|{relativePath}|{job.Name}");
                }
            }
        }
    }

    // TRUST-GHA022: Untrusted event data controls cache identity
    private static void CheckUntrustedEventInCacheKey(
        string content,
        string relativePath,
        List<Finding> findings)
    {
        var untrustedEventFields = new[]
        {
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.comment.body"
        };

        var lines = content.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var cacheUsesByLine = new HashSet<int>();
        var currentUsesLine = -1;
        var currentUsesIndent = -1;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var indent = GetIndentation(line);
            if (currentUsesLine >= 0 && indent <= currentUsesIndent)
            {
                currentUsesLine = -1;
                currentUsesIndent = -1;
            }

            if (line.Contains("uses:", StringComparison.OrdinalIgnoreCase) &&
                line.Contains("actions/cache@", StringComparison.OrdinalIgnoreCase))
            {
                currentUsesLine = i;
                currentUsesIndent = indent;
                cacheUsesByLine.Add(i);
            }
        }

        foreach (var lineNumber in cacheUsesByLine.OrderBy(value => value))
        {
            var stepEnd = FindStepEnd(lines, lineNumber);
            for (var i = lineNumber + 1; i < stepEnd; i++)
            {
                if (IsBlankOrComment(lines[i]))
                {
                    continue;
                }

                if (!ContainsCacheKeyDeclaration(lines[i]))
                {
                    continue;
                }

                foreach (var field in untrustedEventFields)
                {
                    if (!lines[i].Contains(field, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    AddFinding(
                        findings,
                        "TRUST-GHA022",
                        "Untrusted event data controls cache identity",
                        Severity.Medium,
                        "Avoid using untrusted event data such as PR titles in cache keys. Cache poisoning may allow an attacker to control which cache entry is restored.",
                        relativePath,
                        $"Cache key or restore-keys contains untrusted event data in a cache step: {field}",
                        i + 1,
                        Confidence.Medium,
                        identityKey: $"gha022|{relativePath}|{i + 1}|{field}");
                    goto NextCacheStep;
                }
            }

            NextCacheStep:;
        }
    }

    // Migrated: TRUST-GHA009 — Release workflow may publish without test dependency
    private static void CheckReleaseWithoutTestDependency(
        string relativePath,
        GitHubWorkflowModel model,
        List<Finding> findings)
    {
        var jobsByName = model.Jobs;

        foreach (var job in jobsByName.Values)
        {
            if (!IsPublishOrReleaseJob(job))
            {
                continue;
            }

            var hasStrictValidationDependency = JobTransitivelyNeedsStrictValidation(job.Name, jobsByName);
            if (!hasStrictValidationDependency || JobRunsRegardlessOfNeedsResult(job))
            {
                AddFinding(
                    findings,
                    "TRUST-GHA009",
                    "Release workflow may publish without test dependency",
                    Severity.High,
                    "Make release or publish jobs depend on a test or CI job before publishing artifacts or packages.",
                    relativePath,
                    BuildReleaseDependencyMessage(job.Name, jobsByName),
                    job.StartLine,
                    Confidence.Medium,
                    identityKey: $"gha009|{relativePath}|{job.Name}");
            }
        }
    }

    // Migrated: TRUST-GHA016 — Workflow-level write permissions are overly broad
    private static void CheckWorkflowWritePermissions(
        string content,
        string relativePath,
        GitHubWorkflowModel model,
        List<Finding> findings)
    {
        var writeScopes = new[] { "contents", "packages", "actions", "pull-requests", "issues", "checks", "deployments" };

        foreach (var (scope, value) in model.WorkflowPermissions)
        {
            if (writeScopes.Contains(scope, StringComparer.OrdinalIgnoreCase) &&
                value.Equals("write", StringComparison.OrdinalIgnoreCase))
            {
                AddFinding(
                    findings,
                    "TRUST-GHA016",
                    "Workflow-level write permissions are overly broad",
                    Severity.Medium,
                    "Reduce permissions to least privilege per job. Avoid broad write at the workflow level.",
                    relativePath,
                    $"Workflow-level permissions grant {scope}:write.",
                    line: null,
                    confidence: Confidence.Medium,
                    identityKey: $"gha016|{relativePath}|{scope}|write");
                return;
            }
        }
    }

    private static bool IsPublishOrReleaseJob(GitHubJobModel job)
    {
        var publishKeywords = new[]
        {
            "gh release", "npm publish", "dotnet nuget push", "nuget push",
            "twine upload", "docker push", "docker buildx build"
        };

        foreach (var step in job.Steps)
        {
            if (step.Run is not null)
            {
                foreach (var keyword in publishKeywords)
                {
                    if (step.Run.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            if (step.Uses is not null)
            {
                foreach (var keyword in publishKeywords)
                {
                    if (step.Uses.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static bool JobTransitivelyNeedsStrictValidation(
        string jobName,
        IReadOnlyDictionary<string, GitHubJobModel> jobs)
    {
        if (!jobs.TryGetValue(jobName, out var job))
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>(job.Needs);

        while (stack.Count > 0)
        {
            var dependency = stack.Pop();
            if (!seen.Add(dependency))
            {
                continue;
            }

            if (jobs.TryGetValue(dependency, out var dependencyJob))
            {
                if (IsStrictValidationJob(dependencyJob))
                {
                    return true;
                }

                foreach (var nested in dependencyJob.Needs)
                {
                    stack.Push(nested);
                }
            }
        }

        return false;
    }

    private static bool HasStrictValidationDependency(
        GitHubJobModel job,
        IReadOnlyDictionary<string, GitHubJobModel> jobs)
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

            if (jobs.TryGetValue(dependency, out var dependencyJob))
            {
                if (IsStrictValidationJob(dependencyJob))
                {
                    return true;
                }

                foreach (var nested in dependencyJob.Needs)
                {
                    stack.Push(nested);
                }
            }
        }

        return false;
    }

    private static bool IsStrictValidationJob(GitHubJobModel job)
    {
        return IsValidationName(job.Name) &&
               !IsOptionalValidationName(job.Name) &&
               !JobAllowsValidationFailure(job);
    }

    private static bool JobAllowsValidationFailure(GitHubJobModel job)
    {
        return job.ContinueOnError ||
               job.Steps.Any(step =>
                   step.ContinueOnError &&
                   step.Name is not null &&
                   IsValidationName(step.Name) &&
                   !IsNotificationStepName(step.Name));
    }

    private static bool JobRunsRegardlessOfNeedsResult(GitHubJobModel job)
    {
        return job.IfExpression is not null &&
               job.IfExpression.Contains("always()", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidationName(string name)
    {
        foreach (var hint in ValidationJobNameHints)
        {
            if (name.Contains(hint, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsOptionalValidationName(string name)
    {
        return OptionalValidationHints.Any(hint => name.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsNotificationStepName(string name)
    {
        return NotificationStepHints.Any(hint => name.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsFullCommitSha(string value)
    {
        return value.Length == 40 &&
               value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    }

    private static void CheckReusableWorkflowReference(
        string relativePath,
        List<Finding> findings,
        string uses,
        int line,
        string jobName)
    {
        if (!uses.Contains("/.github/workflows/", StringComparison.Ordinal))
        {
            return;
        }

        if (uses.StartsWith("./", StringComparison.Ordinal) ||
            uses.StartsWith("../", StringComparison.Ordinal))
        {
            return;
        }

        var atIndex = uses.LastIndexOf('@');
        if (atIndex < 0)
        {
            return;
        }

        var refPart = uses[(atIndex + 1)..];
        if (IsFullCommitSha(refPart))
        {
            return;
        }

        AddFinding(
            findings,
            "TRUST-GHA019",
            "Mutable reusable workflow reference",
            Severity.Medium,
            "Pin external reusable workflows to a full commit SHA.",
            relativePath,
            $"Job '{jobName}' references external reusable workflow '{uses}' by mutable ref.",
            line,
            Confidence.High,
            identityKey: $"gha019|{relativePath}|{jobName}|{uses}");
    }

    private static string BuildReleaseDependencyMessage(
        string jobName,
        IReadOnlyDictionary<string, GitHubJobModel> jobs)
    {
        if (!jobs.TryGetValue(jobName, out var job))
        {
            return $"Release or package publishing command was found in job '{jobName}' without a visible strict test dependency.";
        }

        if (JobRunsRegardlessOfNeedsResult(job))
        {
            return $"Release or package publishing command was found in job '{jobName}' with if: always(), which can bypass failed validation jobs.";
        }

        if (job.Needs.Any(need => jobs.TryGetValue(need, out var dependency) && JobAllowsValidationFailure(dependency)))
        {
            return $"Release or package publishing command was found in job '{jobName}', but its validation dependency is allowed to fail.";
        }

        return $"Release or package publishing command was found in job '{jobName}' without a visible strict test dependency.";
    }

    private static bool ContainsCacheKeyDeclaration(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.StartsWith("key:", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("restore-keys:", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("-", StringComparison.Ordinal);
    }

    private static int FindStepEnd(string[] lines, int stepStart)
    {
        var stepIndent = GetIndentation(lines[stepStart]);
        for (var i = stepStart + 1; i < lines.Length; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            if (GetIndentation(lines[i]) <= stepIndent)
            {
                return i;
            }
        }

        return lines.Length;
    }

    private static bool IsBlankOrComment(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.Length == 0 || trimmed[0] == '#';
    }

    private static int GetIndentation(string line)
    {
        var count = 0;
        foreach (var c in line)
        {
            if (c == ' ')
            {
                count++;
            }
            else if (c == '\t')
            {
                count += 4;
            }
            else
            {
                break;
            }
        }

        return count;
    }

    private static void AddFinding(
        List<Finding> findings,
        string ruleId,
        string title,
        Severity severity,
        string recommendation,
        string path,
        string message,
        int? line = null,
        Confidence confidence = Confidence.High,
        string? identityKey = null)
    {
        var evidence = line.HasValue
            ? new Evidence("workflow-job", message, path, line.Value)
            : new Evidence("workflow", message, path);

        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.CiCd,
            severity,
            confidence,
            message,
            [evidence],
            new Recommendation(recommendation),
            IdentityKey: identityKey));
    }
}
