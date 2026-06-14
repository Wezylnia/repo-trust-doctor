using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Reporting;

public static class FindingFingerprinter
{
    public static IReadOnlyList<Finding> AddFingerprints(IReadOnlyList<Finding> findings) =>
        FindingIdentity.AddFingerprints(findings);

    public static string Compute(Finding finding) => FindingIdentity.Compute(finding);
}
