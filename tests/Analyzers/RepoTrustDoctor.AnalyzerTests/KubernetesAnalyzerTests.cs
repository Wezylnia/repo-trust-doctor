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
        File.WriteAllText(Path.Combine(fixture.Path, "app.yaml"), """
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

    [Fact]
    public async Task AnalyzeAsync_SecurePod_NoPrivilegedOrHostNamespace()
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
                  readOnlyRootFilesystem: true
                  allowPrivilegeEscalation: false
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S001");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S002");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S003");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S004");
    }

    [Fact]
    public async Task AnalyzeAsync_ConfigMap_NoSecretFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "configmap.yaml"), """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: myconfig
        data:
          key: value
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S005");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S003");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S004");
    }

    // ── K8S006: hostPath volume ───────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsHostPathVolume()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                image: nginx
              volumes:
              - name: host-data
                hostPath:
                  path: /var/run
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S006");
    }

    [Fact]
    public async Task AnalyzeAsync_ConfigMapWithHostPathString_NoK8S006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.yaml"), """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: docs
        data:
          readme: "This is about hostPath volumes"
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S006");
    }

    // ── K8S007: capabilities add ──────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsCapabilityAdd()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                image: nginx
                securityContext:
                  capabilities:
                    add: ["SYS_ADMIN"]
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S007");
    }

    [Fact]
    public async Task AnalyzeAsync_CapabilityDropOnly_NoK8S007()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                image: nginx
                securityContext:
                  capabilities:
                    drop: ["ALL"]
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S007");
    }

    // ── K8S008: privilege escalation ──────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsPrivilegeEscalation()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                image: nginx
                securityContext:
                  allowPrivilegeEscalation: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-K8S008");
    }

    [Fact]
    public async Task AnalyzeAsync_PrivilegeEscalationFalse_NoK8S008()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: app
                image: nginx
                securityContext:
                  allowPrivilegeEscalation: false
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S008");
    }

    [Theory]
    [InlineData("staging/src/k8s.io/api/testdata/HEAD/apps.v1.Deployment.yaml")]
    [InlineData("test/manifests/deployment.yaml")]
    [InlineData("testing/manifests/deployment.yaml")]
    [InlineData("examples/manifests/deployment.yaml")]
    [InlineData("samples/manifests/deployment.yaml")]
    [InlineData("pkg/server/testing/deployment.yaml")]
    [InlineData("integration-test/k8s/deployment.yaml")]
    [InlineData("dockerTest/k8s/deployment.yaml")]
    public async Task AnalyzeAsync_SkipsExampleAndFixtureManifests(string relativePath)
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              hostNetwork: true
              containers:
              - name: app
                securityContext:
                  privileged: true
                  allowPrivilegeEscalation: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}
