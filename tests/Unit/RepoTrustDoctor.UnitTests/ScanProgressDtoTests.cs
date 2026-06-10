using System.Text.Json;
using System.Text.Json.Serialization;
using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.UnitTests;

public sealed class ScanProgressDtoTests
{
    [Fact]
    public void ScanLifecycleStates_CanRepresentSuccessfulScanOrder()
    {
        var expected = new[]
        {
            ScanLifecycleState.Queued,
            ScanLifecycleState.PreparingRepository,
            ScanLifecycleState.RunningFastModules,
            ScanLifecycleState.RunningStaticAnalyzers,
            ScanLifecycleState.RunningDependencyAnalyzers,
            ScanLifecycleState.RunningSecurityAnalyzers,
            ScanLifecycleState.Scoring,
            ScanLifecycleState.Reporting,
            ScanLifecycleState.Completed
        };

        Assert.True(expected.SequenceEqual(expected.OrderBy(state => (int)state)));
    }

    [Fact]
    public void ScanProgressDto_CanRepresentCompletedWithWarningsModule()
    {
        var progress = new ScanProgressDto(
            Guid.NewGuid(),
            ScanLifecycleState.RunningStaticAnalyzers,
            DateTimeOffset.UtcNow,
            [new ScanModuleProgressDto("dependency-risk", "Dependency Risk", AnalysisCategory.Dependencies, ModuleStatus.CompletedWithWarnings, 2, "Registry timeout.")],
            CompletedModuleCount: 1,
            TotalModuleCount: 2);

        Assert.Equal(ModuleStatus.CompletedWithWarnings, progress.Modules[0].Status);
        Assert.Equal(0.5, progress.CompletionRatio);
    }

    [Fact]
    public void ScanProgressDto_CanRepresentCancellation()
    {
        var progress = new ScanProgressDto(
            Guid.NewGuid(),
            ScanLifecycleState.Cancelled,
            DateTimeOffset.UtcNow,
            [],
            CompletedModuleCount: 0,
            TotalModuleCount: 0,
            "Scan was cancelled.");

        Assert.Equal(ScanLifecycleState.Cancelled, progress.State);
        Assert.Equal(0, progress.CompletionRatio);
    }

    [Fact]
    public void ScanProgressDto_SerializesDeterministically()
    {
        var progress = new ScanProgressDto(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            ScanLifecycleState.Completed,
            DateTimeOffset.Parse("2026-06-10T00:00:00Z"),
            [new ScanModuleProgressDto("repository-health", "Repository Health", AnalysisCategory.RepositoryHealth, ModuleStatus.Completed, 0)],
            CompletedModuleCount: 1,
            TotalModuleCount: 1);
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };

        var first = JsonSerializer.Serialize(progress, options);
        var second = JsonSerializer.Serialize(progress, options);

        Assert.Equal(first, second);
        Assert.Contains("Completed", first);
        Assert.Contains("repository-health", first);
    }
}
