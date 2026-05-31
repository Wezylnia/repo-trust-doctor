namespace RepoTrustDoctor.AnalyzerTests;

internal sealed class TemporaryRepository : IDisposable
{
    private TemporaryRepository(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public static TemporaryRepository Create()
    {
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"repo-trust-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return new TemporaryRepository(path);
    }

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
