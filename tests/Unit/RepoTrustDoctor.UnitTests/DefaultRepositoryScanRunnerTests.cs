using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;

namespace RepoTrustDoctor.UnitTests;

public sealed class DefaultRepositoryScanRunnerTests
{
    [Fact]
    public async Task RunAsync_CompletesFastStaticScan_ForLocalRepository()
    {
        using var fixture = TemporaryDirectory.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), """
        # Test Project

        ## Installation

        dotnet tool install example

        ## Usage

        example scan .
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "LICENSE"), "Apache-2.0");
        File.WriteAllText(Path.Combine(fixture.Path, "SECURITY.md"), "Report vulnerabilities privately.");

        var scan = await new DefaultRepositoryScanRunner().RunAsync(
            new ScanRequestOptions(fixture.Path, AnalysisDepth.Fast, TrustProfile.ProductionDependency),
            CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, scan.Status);
        Assert.Equal(AnalysisDepth.Fast, scan.Depth);
        Assert.Contains(scan.Modules, module => module.ModuleId == "repository-health");
    }
}
