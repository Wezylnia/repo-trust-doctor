using RepoTrustDoctor.Infrastructure.Git;

namespace RepoTrustDoctor.UnitTests;

public sealed class RepositoryWorkspaceTests
{
    [Fact]
    public void ForLocalPath_ReturnsAbsolutePath()
    {
        using var fixture = TemporaryDirectory.Create();

        using var workspace = RepositoryWorkspace.ForLocalPath(fixture.Path);

        Assert.Equal(fixture.Path, workspace.Target);
        Assert.Equal(System.IO.Path.GetFullPath(fixture.Path), workspace.Path);
    }

    [Fact]
    public async Task CloneFromUrlAsync_RejectsNonHttpUrls()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RepositoryWorkspace.CloneFromUrlAsync("file:///tmp/repo", CancellationToken.None));
    }

    [Theory]
    [InlineData("http://github.com/owner/repo.git")]
    [InlineData("https://gitlab.com/owner/repo.git")]
    [InlineData("https://localhost/owner/repo.git")]
    [InlineData("https://127.0.0.1/owner/repo.git")]
    [InlineData("https://github.com/owner/repo.git?token=secret")]
    public async Task CloneFromUrlAsync_RejectsNonAllowlistedOrUnsafeUrls(string url)
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RepositoryWorkspace.CloneFromUrlAsync(url, CancellationToken.None));
    }

    [Fact]
    public async Task CloneFromUrlAsync_RejectsUrlsWithCredentials()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RepositoryWorkspace.CloneFromUrlAsync("https://token@example.com/owner/repo.git", CancellationToken.None));
    }

    [Theory]
    [InlineData("https://secretToken123@example.com/owner/repo.git", "secretToken123")]
    [InlineData("https://user:secretPassword456@example.com/owner/repo.git", "secretPassword456")]
    [InlineData("https://github.com/owner/repo.git#secretFragment789", "secretFragment789")]
    public async Task CloneFromUrlAsync_RejectsDangerousUrlsAndRedactsVerbatim(string url, string sensitivePart)
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            RepositoryWorkspace.CloneFromUrlAsync(url, CancellationToken.None));

        Assert.NotNull(exception.Message);
        Assert.DoesNotContain(sensitivePart, exception.Message);
        Assert.DoesNotContain(url, exception.Message);
    }

    [Fact]
    public void ForLocalPath_NormalizesAndResolvesToAbsolutePath()
    {
        using var fixture = TemporaryDirectory.Create();

        using var workspace = RepositoryWorkspace.ForLocalPath(fixture.Path);

        Assert.True(System.IO.Path.IsPathRooted(workspace.Path));
        Assert.Equal(System.IO.Path.GetFullPath(fixture.Path), workspace.Path);
    }

    [Fact]
    public void ForLocalPath_PreservesTargetAsGiven()
    {
        using var fixture = TemporaryDirectory.Create();

        using var workspace = RepositoryWorkspace.ForLocalPath(".");

        Assert.Equal(".", workspace.Target);
        Assert.True(Directory.Exists(workspace.Path));
    }
}
