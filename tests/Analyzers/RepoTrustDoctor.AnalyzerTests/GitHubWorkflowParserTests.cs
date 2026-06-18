using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitHubWorkflowParserTests
{
    [Fact]
    public void Parse_TwoSpaceIndentation()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
        """);

        Assert.NotNull(result.Model);
        Assert.Contains("test", result.Model!.Jobs.Keys);
    }

    [Fact]
    public void Parse_FourSpaceIndentation()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
            test:
                runs-on: ubuntu-latest
                steps:
                    - run: echo test
        """);

        Assert.NotNull(result.Model);
        Assert.Contains("test", result.Model!.Jobs.Keys);
    }

    [Fact]
    public void Parse_CommentsAndBlankLines()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        # This is a comment
        on: [push]

        jobs:
          # Test job
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
        """);

        Assert.NotNull(result.Model);
        Assert.Contains("test", result.Model!.Jobs.Keys);
    }

    [Fact]
    public void Parse_MultipleJobs()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: echo lint
        """);

        Assert.Equal(2, result.Model!.Jobs.Count);
    }

    [Fact]
    public void Parse_ScalarNeeds()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          publish:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        Assert.Equal(["test"], result.Model!.Jobs["publish"].Needs);
    }

    [Fact]
    public void Parse_ListFormNeeds()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: echo lint
          publish:
            needs: [test, lint]
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        Assert.Equal(["test", "lint"], result.Model!.Jobs["publish"].Needs);
    }

    [Fact]
    public void Parse_JobLevelPermissions()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - run: echo test
        """);

        Assert.Equal("read", result.Model!.WorkflowPermissions["contents"]);
        Assert.Equal("write", result.Model.Jobs["test"].Permissions["contents"]);
    }

    [Fact]
    public void Parse_StepLevelContinueOnError()
    {
        var result = GitHubWorkflowParser.Parse("""
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Run security scan
                run: echo scan
                continue-on-error: true
        """);

        Assert.True(result.Model!.Jobs["test"].Steps[0].ContinueOnError);
    }

    [Fact]
    public async Task Parse_MalformedWorkflow_DoesNotThrow()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push
        jobs:
          test
            runs-on: ubuntu-latest
              - run: echo test
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Equal(ModuleStatus.CompletedWithWarnings, result.Status);
        Assert.NotEmpty(result.Warnings ?? []);
        Assert.NotNull(result);
    }
}
