using RepoTrustDoctor.Analyzers.Kubernetes;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class KubernetesAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsPrivilegedContainer()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                securityContext:
                  privileged: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsHostNamespace()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              hostNetwork: true
              containers:
              - name: app
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsMissingRunAsNonRoot()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsWritableRootFilesystem()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                securityContext:
                  runAsNonRoot: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S004");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsSecretManifest()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "secret.yaml"), """
        apiVersion: v1
        kind: Secret
        metadata:
          name: mysecret
        data:
          password: cGFzc3dvcmQ=
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S005");
    }

    [Fact]
    public async Task AnalyzeAsync_IrrelevantFiles_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "not a k8s manifest");

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}
