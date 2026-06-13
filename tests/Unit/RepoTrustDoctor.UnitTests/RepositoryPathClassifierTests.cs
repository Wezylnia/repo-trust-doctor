using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.UnitTests;

public sealed class RepositoryPathClassifierTests
{
    [Theory]
    [InlineData("tests/Fixtures/.env", RepositoryPathClassification.Test | RepositoryPathClassification.Fixture)]
    [InlineData("src/MyProject.Tests/AuthTests.cs", RepositoryPathClassification.Test)]
    [InlineData("docs/examples/k8s/deployment.yaml", RepositoryPathClassification.Documentation | RepositoryPathClassification.Example)]
    [InlineData("examples/demo/package.json", RepositoryPathClassification.Example)]
    [InlineData("internal/command/e2etest/testdata/main.tf", RepositoryPathClassification.Fixture)]
    [InlineData("packages/app/src/generated/client.ts", RepositoryPathClassification.Generated)]
    [InlineData("src/DefaultBuilder/samples/SampleApp/Dockerfile", RepositoryPathClassification.Example)]
    [InlineData("src/Analyzers/Security/SecretQuickScanAnalyzer.cs", RepositoryPathClassification.AnalyzerImplementation)]
    [InlineData("scripts/release/package.ts", RepositoryPathClassification.Tooling)]
    [InlineData("extensions/copilot/script/generateReport.ts", RepositoryPathClassification.Tooling)]
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
