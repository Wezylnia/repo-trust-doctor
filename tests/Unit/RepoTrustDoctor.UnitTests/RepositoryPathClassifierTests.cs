using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.UnitTests;

public sealed class RepositoryPathClassifierTests
{
    [Theory]
    [InlineData("tests/Fixtures/.env", RepositoryPathClassification.Test | RepositoryPathClassification.Fixture)]
    [InlineData("src/MyProject.Tests/AuthTests.cs", RepositoryPathClassification.Test)]
    [InlineData("docs/examples/k8s/deployment.yaml", RepositoryPathClassification.Documentation | RepositoryPathClassification.Example)]
    [InlineData("changelogs/fragments/fix.yml", RepositoryPathClassification.Documentation)]
    [InlineData("guides/assets/javascripts/application.js", RepositoryPathClassification.Documentation)]
    [InlineData("examples/demo/package.json", RepositoryPathClassification.Example)]
    [InlineData("internal/command/e2etest/testdata/main.tf", RepositoryPathClassification.Fixture)]
    [InlineData("packages/app/src/generated/client.ts", RepositoryPathClassification.Generated)]
    [InlineData("staging/src/k8s.io/cli-runtime/artifacts/guestbook/frontend-controller.yaml", RepositoryPathClassification.Generated | RepositoryPathClassification.Example)]
    [InlineData("staging/src/k8s.io/kms/internal/plugins/_mock/kms.yaml", RepositoryPathClassification.Fixture)]
    [InlineData("src/DefaultBuilder/samples/SampleApp/Dockerfile", RepositoryPathClassification.Example)]
    [InlineData("src/Analyzers/Security/SecretQuickScanAnalyzer.cs", RepositoryPathClassification.AnalyzerImplementation)]
    [InlineData("scripts/release/package.ts", RepositoryPathClassification.Tooling)]
    [InlineData("extensions/copilot/script/generateReport.ts", RepositoryPathClassification.Tooling)]
    [InlineData("devenv/docker/blocks/prometheus/docker-compose.yaml", RepositoryPathClassification.Tooling)]
    [InlineData(".citools/src/golangci-lint/go.mod", RepositoryPathClassification.Tooling)]
    [InlineData(".azure-pipelines/templates/test.yml", RepositoryPathClassification.Tooling)]
    [InlineData("third_party/go/pkg/client.go", RepositoryPathClassification.Vendored)]
    [InlineData("deps/openssl/openssl/apps/server.pem", RepositoryPathClassification.Vendored)]
    [InlineData("src/core/tsi/test_creds/server.key", RepositoryPathClassification.Test | RepositoryPathClassification.Fixture)]
    [InlineData("pkg/tls/test-certs/client.pem", RepositoryPathClassification.Test | RepositoryPathClassification.Fixture)]
    [InlineData("src/python/grpcio_tests/tests_py3_only/client.py", RepositoryPathClassification.Test)]
    public void Classify_ReturnsExpectedFlags(string path, RepositoryPathClassification expected)
    {
        var classification = RepositoryPathClassifier.Classify(path);

        Assert.True(classification.HasAny(expected), $"{path} was classified as {classification}, expected {expected}.");
    }

    [Fact]
    public void IsNonProductionEvidencePath_DoesNotClassifyNormalSourceAsLowSignal()
    {
        Assert.False(RepositoryPathClassifier.IsNonProductionEvidencePath("src/Auth/TokenService.cs"));
    }

    [Fact]
    public void IsDocumentationPath_MatchesNestedDocumentationFolders()
    {
        Assert.True(RepositoryPathClassifier.IsDocumentationPath("packages/site/docs/keys/public-ca.pem"));
    }
}
