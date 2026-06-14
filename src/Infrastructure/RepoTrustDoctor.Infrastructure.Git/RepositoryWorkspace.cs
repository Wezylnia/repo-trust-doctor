using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace RepoTrustDoctor.Infrastructure.Git;

public sealed class RepositoryWorkspace : IDisposable
{
    private static readonly HashSet<string> AllowedCloneHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com"
    };

    private const int MaxGitOutputChars = 8192;
    private static readonly TimeSpan CloneTimeout = TimeSpan.FromMinutes(5);

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
        var uri = await ValidateRepositoryUrlAsync(repositoryUrl, cancellationToken);

        var workspaceRoot = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "repo-trust-doctor");
        Directory.CreateDirectory(workspaceRoot);
        var clonePath = System.IO.Path.Combine(workspaceRoot, Guid.NewGuid().ToString("N"));

        using var cloneCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cloneCts.CancelAfter(CloneTimeout);
        try
        {
            await RunGitAsync([
                "-c",
                "protocol.file.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "http.followRedirects=false",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--recurse-submodules=no",
                uri.AbsoluteUri,
                clonePath
            ], cloneCts.Token);
            return new RepositoryWorkspace(repositoryUrl, clonePath, ownsDirectory: true);
        }
        catch (OperationCanceledException) when (cloneCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            DeleteDirectoryQuietly(clonePath);
            throw new TimeoutException($"git clone exceeded the {CloneTimeout.TotalMinutes:0}-minute timeout.");
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

    private static async Task<Uri> ValidateRepositoryUrlAsync(
        string value,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Only absolute HTTPS GitHub repository URLs are supported.", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("Repository URLs must not include usernames, passwords, or tokens.", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("Repository URLs must not include URL fragments.", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.Query))
        {
            throw new ArgumentException("Repository URLs must not include query strings.", nameof(value));
        }

        if (!AllowedCloneHosts.Contains(uri.Host))
        {
            throw new ArgumentException("Only github.com repository URLs are supported for remote scans.", nameof(value));
        }

        var addresses = await Dns.GetHostAddressesAsync(uri.Host, cancellationToken);
        if (addresses.Length == 0 || addresses.Any(IsBlockedAddress))
        {
            throw new ArgumentException("Repository host resolved to a blocked network address.", nameof(value));
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

        var standardOutputTask = ReadBoundedAsync(process.StandardOutput, cancellationToken);
        var standardErrorTask = ReadBoundedAsync(process.StandardError, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(standardOutputTask, standardErrorTask);
        }
        catch (OperationCanceledException)
        {
            KillQuietly(process);
            throw;
        }

        if (process.ExitCode != 0)
        {
            var output = string.Join(Environment.NewLine, [standardOutputTask.Result.Trim(), standardErrorTask.Result.Trim()])
                .Trim();
            throw new InvalidOperationException($"git clone failed with exit code {process.ExitCode}: {output}");
        }
    }

    private static async Task<string> ReadBoundedAsync(
        TextReader reader,
        CancellationToken cancellationToken)
    {
        var buffer = new char[1024];
        var output = new char[MaxGitOutputChars];
        var written = 0;
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
            {
                break;
            }

            var remaining = MaxGitOutputChars - written;
            if (remaining <= 0)
            {
                continue;
            }

            var toCopy = Math.Min(read, remaining);
            Array.Copy(buffer, 0, output, written, toCopy);
            written += toCopy;
        }

        return new string(output, 0, written);
    }

    private static void KillQuietly(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best-effort cancellation cleanup.
        }
    }

    private static bool IsBlockedAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10 ||
                   bytes[0] == 127 ||
                   bytes[0] == 169 && bytes[1] == 254 ||
                   bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                   bytes[0] == 192 && bytes[1] == 168 ||
                   bytes[0] == 0 ||
                   bytes[0] >= 224;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal ||
                   address.IsIPv6Multicast ||
                   address.IsIPv6SiteLocal ||
                   address.Equals(IPAddress.IPv6Loopback);
        }

        return true;
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
