namespace RepoTrustDoctor.Analysis.Abstractions;

[Flags]
public enum RepositoryPathClassification
{
    None = 0,
    Test = 1 << 0,
    Fixture = 1 << 1,
    Example = 1 << 2,
    Documentation = 1 << 3,
    Generated = 1 << 4,
    Template = 1 << 5,
    Benchmark = 1 << 6,
    Tooling = 1 << 7,
    Vendored = 1 << 8,
    AnalyzerImplementation = 1 << 9
}

public static class RepositoryPathClassifier
{
    public static RepositoryPathClassification Classify(string relativePath)
    {
        var normalized = Normalize(relativePath);
        var fileName = Path.GetFileNameWithoutExtension(normalized);
        var classification = RepositoryPathClassification.None;

        if (HasSegment(normalized, "tests") ||
            HasSegment(normalized, "test") ||
            HasSegment(normalized, "__tests__") ||
            HasSegment(normalized, "testing") ||
            HasSegment(normalized, "testdata") ||
            HasSegment(normalized, "testfiles") ||
            HasSegment(normalized, "testassets") ||
            HasSegment(normalized, "testcertificates") ||
            ContainsToken(normalized, "integration-test") ||
            ContainsToken(normalized, "integrationtesting") ||
            ContainsToken(normalized, "e2etest") ||
            ContainsToken(normalized, "inttest") ||
            ContainsToken(normalized, "smoke-test") ||
            ContainsToken(normalized, "dockertest") ||
            ContainsToken(normalized, "testfixtures") ||
            ContainsToken(normalized, "javaresttest") ||
            ContainsToken(normalized, "yamlresttest") ||
            ContainsToken(normalized, "rest-tests") ||
            ContainsToken(normalized, "resttests") ||
            fileName.EndsWith("_test", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith("Tests", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith("Test", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".spec", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".test", StringComparison.OrdinalIgnoreCase))
        {
            classification |= RepositoryPathClassification.Test;
        }

        if (HasSegment(normalized, "fixtures") ||
            HasSegment(normalized, "testfixtures") ||
            HasSegment(normalized, "testdata") ||
            HasSegment(normalized, "testfiles") ||
            HasSegment(normalized, "testassets") ||
            HasSegment(normalized, "testcertificates") ||
            ContainsToken(normalized, "fixture"))
        {
            classification |= RepositoryPathClassification.Fixture;
        }

        if (HasSegment(normalized, "examples") ||
            HasSegment(normalized, "example") ||
            HasSegment(normalized, "samples") ||
            HasSegment(normalized, "sample") ||
            HasSegment(normalized, "playground"))
        {
            classification |= RepositoryPathClassification.Example;
        }

        if (HasSegment(normalized, "docs") ||
            HasSegment(normalized, "documentation"))
        {
            classification |= RepositoryPathClassification.Documentation;
        }

        if (HasSegment(normalized, "generated") ||
            HasSegment(normalized, "gen") ||
            HasSegment(normalized, "out") ||
            HasSegment(normalized, "dist") ||
            ContainsToken(normalized, "generated"))
        {
            classification |= RepositoryPathClassification.Generated;
        }

        if (HasSegment(normalized, "templates") ||
            HasSegment(normalized, "template") ||
            ContainsToken(normalized, "projecttemplates") ||
            ContainsToken(normalized, "itemtemplates"))
        {
            classification |= RepositoryPathClassification.Template;
        }

        if (HasSegment(normalized, "benchmarks") ||
            HasSegment(normalized, "benchmark") ||
            HasSegment(normalized, "perf") ||
            ContainsToken(normalized, "benchmark"))
        {
            classification |= RepositoryPathClassification.Benchmark;
        }

        if (HasSegment(normalized, "tools") ||
            HasSegment(normalized, "tooling") ||
            HasSegment(normalized, "ci") ||
            HasSegment(normalized, ".github") ||
            HasSegment(normalized, "build-tools") ||
            HasSegment(normalized, "build-tools-internal"))
        {
            classification |= RepositoryPathClassification.Tooling;
        }

        if (HasSegment(normalized, "vendor") ||
            HasSegment(normalized, "node_modules") ||
            normalized.Contains("/wwwroot/lib/", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/lib/jquery/", StringComparison.OrdinalIgnoreCase))
        {
            classification |= RepositoryPathClassification.Vendored;
        }

        if (HasSegment(normalized, "analyzers"))
        {
            classification |= RepositoryPathClassification.AnalyzerImplementation;
        }

        return classification;
    }

    public static bool IsNonProductionEvidencePath(string relativePath)
    {
        const RepositoryPathClassification nonProduction =
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example |
            RepositoryPathClassification.Documentation |
            RepositoryPathClassification.Generated |
            RepositoryPathClassification.Template |
            RepositoryPathClassification.Benchmark |
            RepositoryPathClassification.Vendored;

        return Classify(relativePath).HasAny(nonProduction);
    }

    public static bool IsTestFixtureExampleOrDocumentationPath(string relativePath)
    {
        const RepositoryPathClassification lowSignal =
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example |
            RepositoryPathClassification.Documentation;

        return Classify(relativePath).HasAny(lowSignal);
    }

    public static bool IsDocumentationPath(string relativePath) =>
        Classify(relativePath).HasAny(RepositoryPathClassification.Documentation);

    public static string Normalize(string relativePath) =>
        relativePath.Replace('\\', '/').TrimStart('/');

    public static bool HasAny(this RepositoryPathClassification classification, RepositoryPathClassification flags) =>
        (classification & flags) != 0;

    private static bool HasSegment(string normalizedPath, string segment) =>
        normalizedPath.Equals(segment, StringComparison.OrdinalIgnoreCase) ||
        normalizedPath.StartsWith(segment + "/", StringComparison.OrdinalIgnoreCase) ||
        normalizedPath.EndsWith("/" + segment, StringComparison.OrdinalIgnoreCase) ||
        normalizedPath.Contains("/" + segment + "/", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsToken(string normalizedPath, string token) =>
        normalizedPath.Contains(token, StringComparison.OrdinalIgnoreCase);
}
