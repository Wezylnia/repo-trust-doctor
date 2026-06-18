using RepoTrustDoctor.Analyzers.Kubernetes;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class KubernetesSecurityContextTests
{
    // ══════════════════════════════════════════
    // PARSER
    // ══════════════════════════════════════════

    [Fact]
    public void Parse_Deployment()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n";
        var d = KubernetesWorkloadParser.Parse("deploy.yaml", y);
        var w = Assert.Single(d.Workloads);
        Assert.Equal("Deployment", w.Kind);
        Assert.Equal("my-app", w.Name);
        Assert.Equal("app", Assert.Single(w.Containers).Name);
    }

    [Fact]
    public void Parse_CronJob()
    {
        var y = "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nj\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - name: w\n            image: busybox\n";
        var d = KubernetesWorkloadParser.Parse("cj.yaml", y);
        var w = Assert.Single(d.Workloads);
        Assert.Equal("CronJob", w.Kind);
        Assert.Equal("w", Assert.Single(w.Containers).Name);
    }

    [Fact]
    public void Parse_Pod()
    {
        var y = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: app\n    image: nginx\n";
        Assert.Equal("Pod", Assert.Single(KubernetesWorkloadParser.Parse("p.yaml", y).Workloads).Kind);
    }

    [Fact]
    public void Parse_MultipleContainers()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: m\nspec:\n  template:\n    spec:\n      containers:\n      - name: a\n        image: nginx\n      - name: b\n        image: redis\n      - name: c\n        image: pg\n";
        var w = Assert.Single(KubernetesWorkloadParser.Parse("m.yaml", y).Workloads);
        Assert.Equal(3, w.Containers.Count);
        Assert.Equal("a", w.Containers[0].Name);
        Assert.Equal("b", w.Containers[1].Name);
        Assert.Equal("c", w.Containers[2].Name);
    }

    [Fact]
    public void Parse_CommentsIgnored()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\n# kind: Pod\nmetadata:\n  # name: ghost\n  name: real\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n";
        var w = Assert.Single(KubernetesWorkloadParser.Parse("c.yaml", y).Workloads);
        Assert.Equal("Deployment", w.Kind);
        Assert.Equal("real", w.Name);
    }

    [Fact]
    public void Parse_Empty_NoThrow()
    {
        var d = KubernetesWorkloadParser.Parse("e.yaml", "");
        Assert.Empty(d.Workloads);
    }

    [Fact]
    public void Parse_Malformed_NoThrow()
    {
        var d = KubernetesWorkloadParser.Parse("b.yaml", "not\nyaml\n");
        Assert.Empty(d.Workloads);
    }

    [Fact]
    public void Parse_NonWorkload_Skipped()
    {
        var y = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: s\ndata:\n  k: v\n";
        Assert.Empty(KubernetesWorkloadParser.Parse("cm.yaml", y).Workloads);
    }

    [Fact]
    public void Parse_AllWorkloadKinds()
    {
        foreach (var k in new[] { "StatefulSet", "DaemonSet", "Job" })
        {
            var y = $"apiVersion: apps/v1\nkind: {k}\nmetadata:\n  name: t\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n";
            Assert.Equal(k, Assert.Single(KubernetesWorkloadParser.Parse("w.yaml", y).Workloads).Kind);
        }
    }

    [Fact]
    public void Parse_InlineCaps()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: c\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n        securityContext:\n          capabilities:\n            add: [\"SYS_ADMIN\", \"NET_RAW\"]\n            drop: [\"ALL\"]\n";
        var c = Assert.Single(Assert.Single(KubernetesWorkloadParser.Parse("caps.yaml", y).Workloads).Containers);
        Assert.Contains("SYS_ADMIN", c.SecurityContext.CapabilityAdds);
    }

    [Fact]
    public void Parse_BlockListCaps()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: c\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n        securityContext:\n          capabilities:\n            add:\n            - SYS_ADMIN\n            - NET_RAW\n            drop:\n            - ALL\n";
        var c = Assert.Single(Assert.Single(KubernetesWorkloadParser.Parse("caps.yaml", y).Workloads).Containers);
        Assert.Contains("ALL", c.SecurityContext.CapabilityDrops);
    }

    [Fact]
    public void Parse_HelmTemplate_Tolerated()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Values.name }}\nspec:\n  template:\n    spec:\n      containers:\n      - name: {{ .Values.cn }}\n        image: {{ .Values.img }}:{{ .Values.tag }}\n";
        Assert.NotNull(KubernetesWorkloadParser.Parse("helm.yaml", y));
    }

    [Fact]
    public void Parse_MultiDocument()
    {
        var y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: first\nspec:\n  template:\n    spec:\n      containers:\n      - name: a1\n        image: nginx\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: second\nspec:\n  template:\n    spec:\n      containers:\n      - name: a2\n        image: redis\n";
        var d = KubernetesWorkloadParser.Parse("m.yaml", y);
        Assert.Equal(2, d.Workloads.Count);
        Assert.Equal("first", d.Workloads[0].Name);
        Assert.Equal("a2", d.Workloads[1].Containers[0].Name);
    }

    // ══════════════════════════════════════════
    // K8S010: SECCOMP
    // ══════════════════════════════════════════

    [Fact]
    public async Task K8S010_PodLevel_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-K8S010");
    }

    [Fact]
    public async Task K8S010_Localhost_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          seccompProfile:\n            type: Localhost\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-K8S010");
    }

    [Fact]
    public async Task K8S010_Missing_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var f = Assert.Single(r.Findings, x => x.RuleId == "TRUST-K8S010");
        Assert.NotEmpty(f.Evidence);
        Assert.False(string.IsNullOrWhiteSpace(f.IdentityKey));
    }

    [Fact]
    public async Task K8S010_Override_ContainerWins()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          seccompProfile:\n            type: Unconfined\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S010");
    }

    // ══════════════════════════════════════════
    // K8S011: RESOURCE LIMITS
    // ══════════════════════════════════════════

    [Fact]
    public async Task K8S011_BothLimits_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        resources:\n          limits:\n            cpu: \"500m\"\n            memory: \"256Mi\"\n");
        Assert.DoesNotContain((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, f => f.RuleId == "TRUST-K8S011");
    }

    [Fact]
    public async Task K8S011_CpuOnly_ReportsMemory()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        resources:\n          limits:\n            cpu: \"500m\"\n");
        var f = Assert.Single((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, x => x.RuleId == "TRUST-K8S011");
        Assert.Contains("memory", Assert.Single(f.Evidence).Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task K8S011_MemoryOnly_ReportsCpu()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        resources:\n          limits:\n            memory: \"256Mi\"\n");
        var f = Assert.Single((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, x => x.RuleId == "TRUST-K8S011");
        Assert.Contains("CPU", Assert.Single(f.Evidence).Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task K8S011_Neither_ReportsBoth()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n");
        var f = Assert.Single((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, x => x.RuleId == "TRUST-K8S011");
        Assert.Contains("CPU", Assert.Single(f.Evidence).Message, StringComparison.OrdinalIgnoreCase);
    }

    // ══════════════════════════════════════════
    // K8S014: CAPABILITIES W/O DROP ALL
    // ══════════════════════════════════════════

    [Fact]
    public async Task K8S014_AddWithDropAll_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          capabilities:\n            add: [\"NET_RAW\"]\n            drop: [\"ALL\"]\n");
        Assert.DoesNotContain((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, f => f.RuleId == "TRUST-K8S014");
    }

    [Fact]
    public async Task K8S014_AddWithoutDropAll_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          capabilities:\n            add: [\"SYS_ADMIN\"]\n");
        var f = Assert.Single((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, x => x.RuleId == "TRUST-K8S014");
        Assert.Contains("SYS_ADMIN", Assert.Single(f.Evidence).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task K8S014_NoAdd_NoReport()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: s\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          runAsNonRoot: true\n");
        Assert.DoesNotContain((await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None)).Findings, f => f.RuleId == "TRUST-K8S014");
    }

    // ══════════════════════════════════════════
    // CROSS-RULE / REGRESSION
    // ══════════════════════════════════════════

    [Fact]
    public async Task MixedContainers()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: mix\nspec:\n  template:\n    spec:\n      containers:\n" +
            "      - name: good\n        image: nginx@sha256:aaaa\n        securityContext:\n          seccompProfile:\n            type: RuntimeDefault\n          capabilities:\n            drop: [\"ALL\"]\n        resources:\n          limits:\n            cpu: \"500m\"\n            memory: \"256Mi\"\n" +
            "      - name: noseccomp\n        image: redis@sha256:bbbb\n        securityContext:\n          capabilities:\n            drop: [\"ALL\"]\n        resources:\n          limits:\n            cpu: \"500m\"\n            memory: \"256Mi\"\n" +
            "      - name: bad\n        image: pg@sha256:cccc\n        securityContext:\n          capabilities:\n            add: [\"SYS_ADMIN\"]\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var s = r.Findings.Where(f => f.RuleId == "TRUST-K8S010").ToList();
        Assert.Equal(2, s.Count);
        Assert.Single(r.Findings, f => f.RuleId == "TRUST-K8S011");
        Assert.Single(r.Findings, f => f.RuleId == "TRUST-K8S014");
    }

    [Fact]
    public async Task StableIdentityKeys()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: id\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx@sha256:aaaa\n        securityContext:\n          capabilities:\n            add: [\"SYS_ADMIN\"]\n");
        var a = new KubernetesAnalyzer();
        var r1 = await a.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await a.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        foreach (var rid in new[] { "TRUST-K8S010", "TRUST-K8S011", "TRUST-K8S014" })
            Assert.Equal(r1.Findings.First(f => f.RuleId == rid).IdentityKey, r2.Findings.First(f => f.RuleId == rid).IdentityKey);
    }

    [Fact]
    public async Task ExistingRulesStillFire()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "d.yaml"), "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: classic\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n      - name: app\n        image: nginx\n        securityContext:\n          privileged: true\n          allowPrivilegeEscalation: true\n          capabilities:\n            add: [\"SYS_ADMIN\"]\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S001");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S002");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S007");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S008");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S010");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S011");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-K8S014");
    }

    [Fact]
    public async Task MalformedYaml_NoCrash()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "broken.yaml"), "apiVersion: apps/v1\nkind: Deployment\nthis is broken\n{{ .Values.x }}\n  bad: indentation\n");
        var r = await new KubernetesAnalyzer().AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.NotNull(r);
    }
}
