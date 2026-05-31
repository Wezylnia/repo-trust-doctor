using System.Diagnostics;

namespace RepoTrustDoctor.Infrastructure.Git;

public sealed class RepositoryWorkspace : IDisposable
{
    private readonly bool ownsDirectory;

    private RepositoryWorkspace(string target, string path, bool ownsDirectory)
    {
        Target = target;
        Path = path;
        this.ownsDirectory = ownsDirectory;
    }

    public string Target { get; }

    public string Path { get; }

    public static RepositoryWorkspace ForLocalPath(string target)
    {
        var path = System.IO.Path.GetFullPath(target);
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"Repository path does not exist: {path}");
        }

        return new RepositoryWorkspace(target, path, ownsDirectory: false);
    }

    public static async Task<RepositoryWorkspace> CloneFromUrlAsync(
        string repositoryUrl,
        CancellationToken cancellationToken)
    {
        var uri = ValidateRepositoryUrl(repositoryUrl);

        var workspaceRoot = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "repo-trust-doctor");
        Directory.CreateDirectory(workspaceRoot);
        var clonePath = System.IO.Path.Combine(workspaceRoot, Guid.NewGuid().ToString("N"));

        try
        {
            await RunGitAsync([
                "-c",
                "protocol.file.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--recurse-submodules=no",
                uri.AbsoluteUri,
                clonePath
            ], cancellationToken);
            return new RepositoryWorkspace(repositoryUrl, clonePath, ownsDirectory: true);
        }
        catch
        {
            DeleteDirectoryQuietly(clonePath);
            throw;
        }
    }

    public void Dispose()
    {
        if (ownsDirectory)
        {
            DeleteDirectoryQuietly(Path);
        }
    }

    private static Uri ValidateRepositoryUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Only absolute http and https repository URLs are supported.", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("Repository URLs must not include usernames, passwords, or tokens.", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("Repository URLs must not include URL fragments.", nameof(value));
        }

        return uri;
    }

    private static async Task RunGitAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "git",
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start git.");
        }

        var standardError = await process.StandardError.ReadToEndAsync(cancellationToken);
        var standardOutput = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            var output = string.Join(Environment.NewLine, [standardOutput.Trim(), standardError.Trim()])
                .Trim();
            throw new InvalidOperationException($"git clone failed with exit code {process.ExitCode}: {output}");
        }
    }

    private static void DeleteDirectoryQuietly(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // Temporary clone cleanup must not hide the original scan result.
        }
    }
}
