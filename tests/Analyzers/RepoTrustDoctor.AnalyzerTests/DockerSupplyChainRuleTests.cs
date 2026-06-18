using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DockerSupplyChainRuleTests
{
    private static readonly DockerBasicAnalyzer Analyzer = new();

    // ══════════════════════════════════════════
    // TRUST-DOCKER013: External COPY --from not digest-pinned
    // ══════════════════════════════════════════

    [Fact]
    public async Task DOCKER013_ExternalImageWithTag_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20 AS build
        RUN echo build

        FROM alpine:3.20
        COPY --from=nginx:latest /usr/share/nginx/html /app
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var f = Assert.Single(r.Findings, x => x.RuleId == "TRUST-DOCKER013");
        Assert.Contains("nginx:latest", f.IdentityKey);
    }

    [Fact]
    public async Task DOCKER013_ExternalImageWithDigest_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20 AS build
        RUN echo build

        FROM alpine:3.20
        COPY --from=nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /usr/share/nginx/html /app
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER013");
    }

    [Fact]
    public async Task DOCKER013_StageAlias_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM golang:1.23 AS builder
        RUN go build -o /app ./cmd/app

        FROM alpine:3.20
        COPY --from=builder /app /app
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER013");
    }

    [Fact]
    public async Task DOCKER013_ExternalRegistryWithTag_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20 AS build
        RUN echo build

        FROM alpine:3.20
        COPY --from=ghcr.io/org/tool:v1 /out /app
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER013");
    }

    [Fact]
    public async Task DOCKER013_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        COPY --from=redis:latest /data /data
        USER app
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(x => x.RuleId == "TRUST-DOCKER013").IdentityKey;
        var k2 = r2.Findings.First(x => x.RuleId == "TRUST-DOCKER013").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("docker013|", k1);
    }

    [Fact]
    public async Task DOCKER013_RequiredFields()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        COPY --from=busybox:latest /bin/sh /sh
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.All(r.Findings.Where(x => x.RuleId == "TRUST-DOCKER013"), f =>
        {
            Assert.NotEmpty(f.Evidence);
            Assert.False(string.IsNullOrWhiteSpace(f.Recommendation.Message));
            Assert.False(string.IsNullOrWhiteSpace(f.IdentityKey));
        });
    }

    // ══════════════════════════════════════════
    // TRUST-DOCKER015: Package-manager cache in layer
    // ══════════════════════════════════════════

    [Fact]
    public async Task DOCKER015_AptNoCleanup_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apt-get update && apt-get install -y curl
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_AptWithCleanup_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_CleanupInSeparateRun_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apt-get update && apt-get install -y curl
        RUN rm -rf /var/lib/apt/lists/*
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_ApkNoCache_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apk add --no-cache curl
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_ApkWithoutNoCache_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apk add curl
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_YumWithCleanAll_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM centos:7
        RUN yum install -y curl && yum clean all
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_DnfWithoutCleanAll_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM fedora:40
        RUN dnf install -y curl
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
    }

    [Fact]
    public async Task DOCKER015_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        RUN apt-get install -y curl
        USER app
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(x => x.RuleId == "TRUST-DOCKER015").IdentityKey;
        var k2 = r2.Findings.First(x => x.RuleId == "TRUST-DOCKER015").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("docker015|", k1);
    }

    // ══════════════════════════════════════════
    // TRUST-DOCKER016: Secret-like ARG
    // ══════════════════════════════════════════

    [Fact]
    public async Task DOCKER016_SecretLikeArg_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG API_TOKEN=default
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_PasswordArg_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG PASSWORD
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_SafeArg_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG VERSION=1.0
        ARG TARGETARCH
        ARG BUILD_CONFIGURATION=Release
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_SecretMountDoesNotSuppress()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG API_TOKEN
        RUN --mount=type=secret,id=API_TOKEN echo "secret used"
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        // BuildKit secret mount does NOT suppress the ARG finding.
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_PrivateRegistry_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG PRIVATE_REGISTRY
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        // PRIVATE_REGISTRY ends with "REGISTRY", not a secret suffix token.
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_CertificatePath_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG CERTIFICATE_PATH
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_SigningAlgorithm_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG SIGNING_ALGORITHM
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_PrivateKeyArg_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG PRIVATE_KEY
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_SigningCredentials_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG SIGNING_CREDENTIALS
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task DOCKER016_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG PRIVATE_KEY
        USER app
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(x => x.RuleId == "TRUST-DOCKER016").IdentityKey;
        var k2 = r2.Findings.First(x => x.RuleId == "TRUST-DOCKER016").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("docker016|", k1);
    }

    [Fact]
    public async Task DOCKER016_RequiredFields()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG CLIENT_SECRET
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.All(r.Findings.Where(x => x.RuleId == "TRUST-DOCKER016"), f =>
        {
            Assert.NotEmpty(f.Evidence);
            Assert.False(string.IsNullOrWhiteSpace(f.Recommendation.Message));
            Assert.False(string.IsNullOrWhiteSpace(f.IdentityKey));
        });
    }

    // ══════════════════════════════════════════
    // CROSS-RULE / REGRESSION
    // ══════════════════════════════════════════

    [Fact]
    public async Task AllThreeNewRules_CanFireTogether()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        ARG PASSWORD
        RUN apt-get install -y curl
        COPY --from=nginx:latest /usr/share/nginx/html /app
        USER app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER013");
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER015");
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016");
    }

    [Fact]
    public async Task MalformedDockerfile_NoCrash()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:3.20
        THIS IS NOT VALID DOCKERFILE SYNTAX
        ARG ???
        COPY -----
        RUN apk add curl
        USER app
        """);

        // Must not throw.
        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task ExistingRulesStillFire()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fx.Path, "Dockerfile"), """
        FROM alpine:latest
        RUN sudo apk add curl
        ARG PASSWORD=secret
        ENV SECRET=value
        COPY --from=redis:latest /data /data
        ADD ./app /app
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        // Existing rules should still fire alongside new ones.
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER002"); // latest tag
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER010"); // sudo
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER005"); // secret ENV
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER009"); // ADD vs COPY
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER013"); // external --from
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-DOCKER016"); // secret ARG
    }
}
