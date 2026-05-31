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

    [Fact]
    public async Task CloneFromUrlAsync_RejectsUrlsWithCredentials()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RepositoryWorkspace.CloneFromUrlAsync("https://token@example.com/owner/repo.git", CancellationToken.None));
    }
}
