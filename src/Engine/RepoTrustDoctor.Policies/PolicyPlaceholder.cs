namespace RepoTrustDoctor.Policies;

public sealed record TrustPolicy(
    string Name,
    int MinimumScore = 80,
    bool TreatCriticalFindingsAsBlocking = true);
