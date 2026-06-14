namespace RepoTrustDoctor.Infrastructure.LocalData;

public sealed record LocalIntelligenceOptions
{
    public string DatabasePath { get; init; } = DefaultDatabasePath();

    public bool ConnectionPoolingEnabled { get; init; } = true;

    public bool RegistryCacheEnabled { get; init; } = true;

    public TimeSpan RegistryCacheTtl { get; init; } = TimeSpan.FromHours(24);

    public bool LocalOsvEnabled { get; init; } = true;

    public bool OsvOnlineFallbackEnabled { get; init; } = true;

    public bool BackgroundRefreshEnabled { get; init; }

    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromHours(24);

    public TimeSpan FullOsvRefreshInterval { get; init; } = TimeSpan.FromDays(7);

    public IReadOnlyList<string> OsvEcosystems { get; init; } =
    [
        "npm",
        "NuGet",
        "PyPI",
        "Maven",
        "Go",
        "crates.io",
        "Packagist",
        "RubyGems",
        "Pub",
        "Hex",
        "SwiftURL"
    ];

    public static LocalIntelligenceOptions CreateDefault() => new();

    private static string DefaultDatabasePath()
    {
        var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localData))
        {
            localData = Path.GetTempPath();
        }

        return Path.Combine(localData, "RepoTrustDoctor", "intelligence.db");
    }
}
