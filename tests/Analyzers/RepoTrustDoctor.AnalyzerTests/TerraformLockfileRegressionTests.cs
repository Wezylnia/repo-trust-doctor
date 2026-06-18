using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Terraform;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class TerraformLockfileRegressionTests
{
    private static readonly TerraformAnalyzer Analyzer = new();

    [Fact]
    public async Task TF007_RequiredProvidersInLaterFile_ReportsRegardlessOfEnumerationOrder()
    {
        using var repository = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(repository.Path, "a-output.tf"), """
        output "name" {
          value = "example"
        }
        """);
        File.WriteAllText(Path.Combine(repository.Path, "z-providers.tf"), """
        terraform {
          required_providers {
            aws = {
              source = "hashicorp/aws"
            }
          }
        }
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var finding = Assert.Single(result.Findings.Where(finding => finding.RuleId == "TRUST-TF007"));
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("z-providers.tf", evidence.FilePath);
        Assert.Equal(2, evidence.LineNumber);
    }

    [Fact]
    public async Task TF007_RequiredProvidersInsideComment_DoesNotReport()
    {
        using var repository = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(repository.Path, "main.tf"), """
        # required_providers {
        #   aws = { source = "hashicorp/aws" }
        # }
        output "name" {
          value = "required_providers"
        }
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-TF007");
    }

    [Fact]
    public async Task TF007_ChecksTerraformDirectoriesIndependently()
    {
        using var repository = TemporaryRepository.Create();
        var firstDirectory = Path.Combine(repository.Path, "infra", "one");
        var secondDirectory = Path.Combine(repository.Path, "infra", "two");
        Directory.CreateDirectory(firstDirectory);
        Directory.CreateDirectory(secondDirectory);

        const string providerConfiguration = """
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws" }
          }
        }
        """;

        File.WriteAllText(Path.Combine(firstDirectory, "main.tf"), providerConfiguration);
        File.WriteAllText(Path.Combine(secondDirectory, "main.tf"), providerConfiguration);
        File.WriteAllText(Path.Combine(firstDirectory, ".terraform.lock.hcl"), "# locked");

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var finding = Assert.Single(result.Findings.Where(finding => finding.RuleId == "TRUST-TF007"));
        Assert.Equal("tf007|infra/two", finding.IdentityKey);
    }
}
