using RepoTrustDoctor.Analyzers.Terraform;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class TerraformLockfileRegressionTests
{
    private static readonly TerraformAnalyzer Analyzer = new();

    [Fact]
    public async Task RequiredProvidersInLaterFileStillReportsMissingLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "a.tf"), """
        output "name" {
          value = "example"
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "z.tf"), """
        terraform {
          required_providers {
            aws = {
              source = "hashicorp/aws"
            }
          }
        }
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var finding = Assert.Single(
            result.Findings,
            candidate => candidate.RuleId == "TRUST-TF007");
        Assert.Equal("z.tf", finding.Evidence[0].FilePath);
    }

    [Fact]
    public async Task RequiredProvidersTextInCommentsAndStringsDoesNotReport()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        # required_providers {
        # }
        output "text" {
          value = "required_providers"
        }
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            candidate => candidate.RuleId == "TRUST-TF007");
    }
}
