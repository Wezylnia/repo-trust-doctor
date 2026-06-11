using RepoTrustDoctor.Analyzers.Terraform;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class TerraformAnalyzerTests
{
    // ── TF001: public ingress ─────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsPublicIngress()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_security_group" "example" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
            type        = "ingress"
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsPublicIngressWithoutTypeProperty()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_security_group" "example" {
          ingress {
            from_port   = 443
            to_port     = 443
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF001");
    }

    [Fact]
    public async Task AnalyzeAsync_EgressOnly_NoTF001()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_security_group" "example" {
          egress {
            cidr_blocks = ["0.0.0.0/0"]
            type        = "egress"
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF001");
    }

    // ── TF002: wildcard IAM ───────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsWildcardIam()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_iam_policy" "bad" {
          policy = jsonencode({
            Statement = [{
              Action   = "*"
              Effect   = "Allow"
              Resource = "*"
            }]
          })
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsWildcardIamJsonPolicy()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_iam_policy" "bad" {
          policy = <<POLICY
        {
          "Statement": [{
            "Action": "*",
            "Effect": "Allow",
            "Resource": "*"
          }]
        }
        POLICY
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF002");
    }

    [Fact]
    public async Task AnalyzeAsync_ActionOnlyWildcard_NoTF002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_iam_policy" "ok" {
          policy = jsonencode({
            Statement = [{
              Action   = "*"
              Resource = "arn:aws:s3:::my-bucket"
            }]
          })
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF002");
    }

    // ── TF003: S3 public ACL ──────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsPublicAcl()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_s3_bucket" "bad" {
          bucket = "bad-bucket"
          acl    = "public-read"
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF003");
    }

    [Fact]
    public async Task AnalyzeAsync_PrivateAcl_NoTF003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_s3_bucket" "good" {
          bucket = "good-bucket"
          acl    = "private"
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF003");
    }

    // ── TF004: S3 encryption ──────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_S3WithoutEncryption_ReportsTF004()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_s3_bucket" "noenc" {
          bucket = "noenc-bucket"
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF004");
    }

    [Fact]
    public async Task AnalyzeAsync_S3WithEncryption_NoTF004()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        resource "aws_s3_bucket" "enc" {
          bucket = "enc-bucket"
          server_side_encryption_configuration {
            rule {
              apply_server_side_encryption_by_default {
                sse_algorithm = "aws:kms"
              }
            }
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF004");
    }

    // ── TF005: provider version ───────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ProviderWithoutVersion_ReportsTF005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = {
              source = "hashicorp/aws"
            }
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF005");
    }

    [Fact]
    public async Task AnalyzeAsync_ProviderWithVersion_NoTF005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = {
              source  = "hashicorp/aws"
              version = "~> 5.0"
            }
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF005");
    }

    // ── TF006: backend encryption ─────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_S3BackendNoEncryption_ReportsTF006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        terraform {
          backend "s3" {
            bucket = "state"
            key    = "terraform.tfstate"
            region = "us-east-1"
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-TF006");
    }

    [Fact]
    public async Task AnalyzeAsync_S3BackendWithEncryption_NoTF006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "main.tf"), """
        terraform {
          backend "s3" {
            bucket  = "state"
            key     = "terraform.tfstate"
            region  = "us-east-1"
            encrypt = true
          }
        }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-TF006");
    }

    [Fact]
    public async Task AnalyzeAsync_LockFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".terraform.lock.hcl"), """
        provider "registry.terraform.io/hashicorp/aws" { version = "5.0" }
        """);

        var analyzer = new TerraformAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}
