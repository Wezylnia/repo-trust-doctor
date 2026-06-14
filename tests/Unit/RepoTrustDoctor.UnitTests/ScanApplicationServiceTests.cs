using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Domain;
using System.Text.Json;

namespace RepoTrustDoctor.UnitTests;

public sealed class ScanApplicationServiceTests
{
    [Fact]
    public void ScanRequestValidator_AcceptsProfileAliasesAndDepths()
    {
        var validator = new ScanRequestValidator();

        var ok = validator.TryCreateOptions(
            new StartScanRequest("https://github.com/owner/repo", "deep", TrustProfile: "enterprise"),
            out var options,
            out _);

        Assert.True(ok);
        Assert.Equal("https://github.com/owner/repo", options.Target);
        Assert.Equal(AnalysisDepth.Deep, options.Depth);
        Assert.Equal(TrustProfile.SecuritySensitiveDependency, options.TrustProfile);
    }

    [Theory]
    [InlineData("ci-cd")]
    [InlineData("container")]
    [InlineData("CiCdTool")]
    [InlineData("ContainerDependency")]
    public void ScanRequestValidator_MergesLegacyAutomationProfilesIntoProduction(string profile)
    {
        var validator = new ScanRequestValidator();

        var ok = validator.TryCreateOptions(
            new StartScanRequest("https://github.com/owner/repo", "fast", TrustProfile: profile),
            out var options,
            out _);

        Assert.True(ok);
        Assert.Equal(TrustProfile.ProductionDependency, options.TrustProfile);
    }

    [Fact]
    public void ScanRequestValidator_RejectsCredentialedUrls()
    {
        var validator = new ScanRequestValidator();

        var ok = validator.TryCreateOptions(new StartScanRequest("https://token@github.com/owner/repo", "fast"), out _, out var error);

        Assert.False(ok);
        Assert.Contains("without credentials", error);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("C:\\Users")]
    [InlineData("http://github.com/owner/repo")]
    [InlineData("https://gitlab.com/owner/repo")]
    [InlineData("https://github.com/owner/repo?token=secret")]
    public void ScanRequestValidator_RejectsNonGitHubApiTargets(string target)
    {
        var validator = new ScanRequestValidator();

        var ok = validator.TryCreateOptions(new StartScanRequest(target, "fast"), out _, out var error);

        Assert.False(ok);
        Assert.Contains("https://github.com", error);
    }

    [Fact]
    public async Task ScanCoordinator_QueuesValidScan()
    {
        var store = new InMemoryScanStore();
        var queue = new InMemoryScanJobQueue();
        var coordinator = new ScanCoordinator(store, queue, new ScanRequestValidator());

        var result = await coordinator.StartAsync(new StartScanRequest("https://github.com/owner/repo", "standard"), CancellationToken.None);
        var job = await queue.DequeueAsync(CancellationToken.None);

        Assert.True(result.Accepted);
        Assert.Equal(result.ScanId, job.ScanId);
        Assert.True(store.TryGet(result.ScanId, out var state));
        Assert.Equal(ScanLifecycleState.Queued, state!.State);
    }

    [Fact]
    public async Task ScanJobProcessor_CompletesScanWithRunnerResult()
    {
        var store = new InMemoryScanStore();
        var queue = new InMemoryScanJobQueue();
        var coordinator = new ScanCoordinator(store, queue, new ScanRequestValidator());
        var result = await coordinator.StartAsync(new StartScanRequest("https://github.com/owner/repo", "fast"), CancellationToken.None);
        var job = await queue.DequeueAsync(CancellationToken.None);
        var processor = new ScanJobProcessor(store, new FakeScanRunner());

        await processor.ProcessAsync(job, CancellationToken.None);

        Assert.True(store.TryGet(result.ScanId, out var state));
        Assert.Equal(ScanLifecycleState.Completed, state!.State);
        Assert.NotNull(state.Result);
        Assert.Equal(100, state.Result.Score.Overall);
        Assert.Equal(1, state.ToStatusResponse().ModuleCount);
        Assert.Equal(0, state.ToStatusResponse().FindingCount);
        Assert.Equal(1, state.ToProgressDto().CompletionRatio);
    }

    [Fact]
    public async Task ScanJobProcessor_MarksFailureWithoutThrowing()
    {
        var store = new InMemoryScanStore();
        var queue = new InMemoryScanJobQueue();
        var coordinator = new ScanCoordinator(store, queue, new ScanRequestValidator());
        var result = await coordinator.StartAsync(new StartScanRequest("https://github.com/owner/repo", "fast"), CancellationToken.None);
        var job = await queue.DequeueAsync(CancellationToken.None);
        var processor = new ScanJobProcessor(store, new ThrowingScanRunner());

        await processor.ProcessAsync(job, CancellationToken.None);

        Assert.True(store.TryGet(result.ScanId, out var state));
        Assert.Equal(ScanLifecycleState.Failed, state!.State);
        Assert.Equal("Scan failed unexpectedly.", state.StatusMessage);
        Assert.DoesNotContain("secret", state.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ScanCoordinator_DoesNotOverwriteCompletedScanOnCancel()
    {
        var store = new InMemoryScanStore();
        var queue = new InMemoryScanJobQueue();
        var coordinator = new ScanCoordinator(store, queue, new ScanRequestValidator());
        var result = await coordinator.StartAsync(new StartScanRequest("https://github.com/owner/repo", "fast"), CancellationToken.None);
        var job = await queue.DequeueAsync(CancellationToken.None);
        var processor = new ScanJobProcessor(store, new FakeScanRunner());
        await processor.ProcessAsync(job, CancellationToken.None);

        var cancelled = coordinator.TryCancel(result.ScanId);

        Assert.True(cancelled);
        Assert.True(store.TryGet(result.ScanId, out var state));
        Assert.Equal(ScanLifecycleState.Completed, state!.State);
        Assert.Equal("Scan completed.", state.StatusMessage);
        Assert.NotNull(state.Result);
    }

    [Fact]
    public async Task ScanJobProcessor_DoesNotOverwriteCancelledScan()
    {
        var store = new InMemoryScanStore();
        var queue = new InMemoryScanJobQueue();
        var coordinator = new ScanCoordinator(store, queue, new ScanRequestValidator());
        var result = await coordinator.StartAsync(new StartScanRequest("https://github.com/owner/repo", "fast"), CancellationToken.None);
        var job = await queue.DequeueAsync(CancellationToken.None);

        Assert.True(coordinator.TryCancel(result.ScanId));
        await new ScanJobProcessor(store, new FakeScanRunner()).ProcessAsync(job, CancellationToken.None);

        Assert.True(store.TryGet(result.ScanId, out var state));
        Assert.Equal(ScanLifecycleState.Cancelled, state!.State);
        Assert.Null(state.Result);
    }

    [Fact]
    public void ScanJsonSerializerOptions_WritesApiEnumsAsStrings()
    {
        var dto = new ScanStatusResponse(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            ".",
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            ScanLifecycleState.Completed,
            DateTimeOffset.Parse("2026-06-10T00:00:00Z"),
            DateTimeOffset.Parse("2026-06-10T00:00:01Z"),
            DateTimeOffset.Parse("2026-06-10T00:00:01Z"),
            "Completed.",
            9,
            3,
            85,
            FinalDecisionKind.SafeToTry);

        var json = JsonSerializer.Serialize(dto, ScanJsonSerializerOptions.Create());

        Assert.Contains("\"depth\":\"Fast\"", json);
        Assert.Contains("\"trustProfile\":\"ProductionDependency\"", json);
        Assert.Contains("\"state\":\"Completed\"", json);
        Assert.Contains("\"decision\":\"SafeToTry\"", json);
        Assert.DoesNotContain("\"state\":8", json);
    }

    private sealed class FakeScanRunner : IRepositoryScanRunner
    {
        public Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
        {
            var now = DateTimeOffset.Parse("2026-06-10T00:00:00Z");
            var scan = new RepositoryScan(
                Guid.NewGuid(),
                options.Target,
                options.Depth,
                options.TrustProfile,
                "test",
                ModuleStatus.Completed,
                now,
                now,
                [new ScanModule("fake", "Fake", AnalysisCategory.RepositoryHealth, ModuleStatus.Completed, now, now, 0)],
                [],
                new TrustScore(100, [], new FinalDecision(FinalDecisionKind.SafeToTry, [])));
            return Task.FromResult(scan);
        }
    }

    private sealed class ThrowingScanRunner : IRepositoryScanRunner
    {
        public Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("boom token=secret");
    }
}
