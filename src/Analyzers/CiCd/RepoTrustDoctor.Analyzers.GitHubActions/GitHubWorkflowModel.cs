namespace RepoTrustDoctor.Analyzers.GitHubActions;

internal sealed record GitHubWorkflowParseResult(
    GitHubWorkflowModel? Model,
    IReadOnlyList<string> Warnings);

internal sealed record GitHubWorkflowModel(
    IReadOnlySet<string> Triggers,
    IReadOnlyDictionary<string, GitHubJobModel> Jobs,
    IReadOnlyDictionary<string, string> WorkflowPermissions);

internal sealed record GitHubJobModel(
    string Name,
    IReadOnlyList<string> Needs,
    string? IfExpression,
    bool ContinueOnError,
    IReadOnlyDictionary<string, string> Permissions,
    IReadOnlyList<GitHubStepModel> Steps,
    string? Uses,
    int StartLine);

internal sealed record GitHubStepModel(
    string? Name,
    string? Uses,
    string? Run,
    bool ContinueOnError,
    IReadOnlyDictionary<string, string> With,
    int StartLine);
