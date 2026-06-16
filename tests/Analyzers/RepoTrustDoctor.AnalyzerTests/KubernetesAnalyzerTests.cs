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
    public async Task AnalyzeAsync_SkipsVendoredManifests()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "vendor", "charts"));
        File.WriteAllText(Path.Combine(fixture.Path, "vendor", "charts", "deployment.yaml"), """
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

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_SkipsKubernetesApiFixtureManifests()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "staging", "src", "k8s.io", "apiserver", "pkg", "endpoints", "handlers", "fieldmanager");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "pod.yaml"), """
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: app
            image: nginx
        """);

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
    public async Task AnalyzeAsync_MixedContainerSecurity_ReportsOnlyUnsafeContainers()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: safe
                securityContext:
                  runAsNonRoot: true
                  readOnlyRootFilesystem: true
              - name: unsafe
                image: nginx
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var runAsNonRoot = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S003");
        var rootFilesystem = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S004");
        Assert.Contains("unsafe", Assert.Single(runAsNonRoot.Evidence).Message, StringComparison.Ordinal);
        Assert.Contains("unsafe", Assert.Single(rootFilesystem.Evidence).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_PodRunAsNonRoot_AppliesToContainers()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              securityContext:
                runAsNonRoot: true
              containers:
              - name: app
                securityContext:
                  readOnlyRootFilesystem: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S003");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-K8S004");
    }

    [Fact]
    public async Task AnalyzeAsync_MultiDocumentPodSecurity_DoesNotApplyAcrossDocuments()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deployment.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              securityContext:
                runAsNonRoot: true
              containers:
              - name: safe
                securityContext:
                  readOnlyRootFilesystem: true
        ---
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: unsafe
                securityContext:
                  readOnlyRootFilesystem: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S003");
        Assert.Contains("unsafe", Assert.Single(finding.Evidence).Message, StringComparison.Ordinal);
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
    public async Task AnalyzeAsync_AggregatesHostPathVolumesPerManifest()
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
              - name: host-logs
                hostPath:
                  path: /var/log
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S006");
        Assert.Contains("2 hostPath", Assert.Single(finding.Evidence).Message, StringComparison.Ordinal);
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

    [Fact]
    public async Task AnalyzeAsync_ReportsCapabilityAddsOnlyForUnsafeContainer()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "deploy.yaml"), """
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
              - name: safe
                image: nginx
                securityContext:
                  capabilities:
                    drop: ["ALL"]
              - name: unsafe
                image: nginx
                securityContext:
                  capabilities:
                    add: ["SYS_ADMIN"]
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S007");
        Assert.Contains("unsafe", Assert.Single(finding.Evidence).Message, StringComparison.Ordinal);
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

    [Fact]
    public async Task AnalyzeAsync_DetectsEphemeralContainerPrivilegeEscalation()
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
                  runAsNonRoot: true
                  readOnlyRootFilesystem: true
                  allowPrivilegeEscalation: false
              ephemeralContainers:
              - name: debugger
                image: busybox
                securityContext:
                  allowPrivilegeEscalation: true
        """);

        var analyzer = new KubernetesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-K8S008");
        Assert.Contains("debugger", Assert.Single(finding.Evidence).Message, StringComparison.Ordinal);
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
