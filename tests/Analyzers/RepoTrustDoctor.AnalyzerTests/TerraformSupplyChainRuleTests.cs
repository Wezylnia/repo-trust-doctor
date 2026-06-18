using RepoTrustDoctor.Analyzers.Terraform;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class TerraformSupplyChainRuleTests
{
    private static readonly TerraformAnalyzer Analyzer = new();

    // ══════════════════════════════════════════
    // TRUST-TF007: Missing lockfile
    // ══════════════════════════════════════════

    [Fact]
    public async Task TF007_HasRequiredProviders_NoLockfile_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = {
              source  = "hashicorp/aws"
            }
          }
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF007");
    }

    [Fact]
    public async Task TF007_HasRequiredProviders_WithLockfile_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = {
              source  = "hashicorp/aws"
            }
          }
        }
        """);
        // Create lockfile
        File.WriteAllText(Path.Combine(fx.Path, ".terraform.lock.hcl"), "# lockfile");

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF007");
    }

    [Fact]
    public async Task TF007_NoRequiredProviders_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        output "hello" {
          value = "world"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF007");
    }

    [Fact]
    public async Task TF007_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws" }
          }
        }
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(f => f.RuleId == "TRUST-TF007").IdentityKey;
        var k2 = r2.Findings.First(f => f.RuleId == "TRUST-TF007").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("tf007|", k1);
    }

    // ══════════════════════════════════════════
    // TRUST-TF008: Mutable module source
    // ══════════════════════════════════════════

    [Fact]
    public async Task TF008_GitSourceBranch_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "vpc" {
          source = "git::https://example.com/vpc-module.git?ref=main"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_GitSourceTag_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "vpc" {
          source = "git::https://example.com/vpc-module.git?ref=v1.0.0"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_GitSourceCommitSha_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "vpc" {
          source = "git::https://example.com/vpc-module.git?ref=abcdef0123456789abcdef0123456789abcdef01"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_NoRef_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "vpc" {
          source = "git::https://example.com/vpc-module.git"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_LocalSource_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "local_module" {
          source = "./modules/my-module"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_RegistryModule_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "vpc" {
          source  = "terraform-aws-modules/vpc/aws"
          version = "5.0.0"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF008");
    }

    [Fact]
    public async Task TF008_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        module "my_mod" {
          source = "git::https://example.com/repo.git?ref=main"
        }
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(f => f.RuleId == "TRUST-TF008").IdentityKey;
        var k2 = r2.Findings.First(f => f.RuleId == "TRUST-TF008").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("tf008|", k1);
    }

    // ══════════════════════════════════════════
    // TRUST-TF009: Publicly accessible database
    // ══════════════════════════════════════════

    [Fact]
    public async Task TF009_RdsPubliclyAccessibleTrue_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_db_instance" "db" {
          publicly_accessible = true
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task TF009_RdsPubliclyAccessibleFalse_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_db_instance" "db" {
          publicly_accessible = false
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task TF009_RdsMissingAttribute_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_db_instance" "db" {
          engine = "postgres"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task TF009_VariableReference_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        variable "public" { default = true }
        resource "aws_db_instance" "db" {
          publicly_accessible = var.public
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task TF009_NotTriggeredInLocals()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        locals {
          note = "publicly_accessible = true"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task TF009_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_db_instance" "mydb" {
          publicly_accessible = true
        }
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(f => f.RuleId == "TRUST-TF009").IdentityKey;
        var k2 = r2.Findings.First(f => f.RuleId == "TRUST-TF009").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("tf009|", k1);
    }

    // ══════════════════════════════════════════
    // TRUST-TF010: KMS key rotation disabled
    // ══════════════════════════════════════════

    [Fact]
    public async Task TF010_RotationFalse_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_kms_key" "key" {
          enable_key_rotation = false
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF010");
    }

    [Fact]
    public async Task TF010_RotationTrue_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_kms_key" "key" {
          enable_key_rotation = true
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF010");
    }

    [Fact]
    public async Task TF010_MissingAttribute_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_kms_key" "key" {
          description = "my key"
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF010");
    }

    [Fact]
    public async Task TF010_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_kms_key" "mykey" {
          enable_key_rotation = false
        }
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(f => f.RuleId == "TRUST-TF010").IdentityKey;
        var k2 = r2.Findings.First(f => f.RuleId == "TRUST-TF010").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("tf010|", k1);
    }

    // ══════════════════════════════════════════
    // TRUST-TF011: S3 public-access block disabled
    // ══════════════════════════════════════════

    [Fact]
    public async Task TF011_AllFlagsDisabled_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket                  = aws_s3_bucket.example.id
          block_public_acls       = false
          block_public_policy     = false
          ignore_public_acls      = false
          restrict_public_buckets = false
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var f = Assert.Single(r.Findings, x => x.RuleId == "TRUST-TF011");
        var msg = Assert.Single(f.Evidence).Message;
        Assert.Contains("block_public_acls", msg);
        Assert.Contains("block_public_policy", msg);
    }

    [Fact]
    public async Task TF011_OneFlagDisabled_Reports()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "example" {
          block_public_acls       = false
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var f = Assert.Single(r.Findings, x => x.RuleId == "TRUST-TF011");
        Assert.Contains("block_public_acls", Assert.Single(f.Evidence).Message);
    }

    [Fact]
    public async Task TF011_AllFlagsEnabled_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "example" {
          block_public_acls       = true
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF011");
    }

    [Fact]
    public async Task TF011_MissingFlags_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket = aws_s3_bucket.example.id
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF011");
    }

    [Fact]
    public async Task TF011_VariableReference_Passes()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "example" {
          block_public_acls = var.block_acls
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "TRUST-TF011");
    }

    [Fact]
    public async Task TF011_IdentityKey_Stable()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_s3_bucket_public_access_block" "mybucket" {
          block_public_acls = false
        }
        """);

        var r1 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var r2 = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        var k1 = r1.Findings.First(f => f.RuleId == "TRUST-TF011").IdentityKey;
        var k2 = r2.Findings.First(f => f.RuleId == "TRUST-TF011").IdentityKey;
        Assert.Equal(k1, k2);
        Assert.StartsWith("tf011|", k1);
    }

    // ══════════════════════════════════════════
    // CROSS-RULE / REGRESSION
    // ══════════════════════════════════════════

    [Fact]
    public async Task MultipleNewRules_FireTogether()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws" }
          }
        }
        module "vpc" {
          source = "git::https://example.com/vpc.git?ref=main"
        }
        resource "aws_db_instance" "db" {
          publicly_accessible = true
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF007");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF008");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF009");
    }

    [Fact]
    public async Task ExistingRulesStillFire()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        resource "aws_security_group" "sg" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        resource "aws_s3_bucket" "b" {
          bucket = "my-bucket"
          acl    = "public-read"
        }
        resource "aws_kms_key" "key" {
          enable_key_rotation = false
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF001");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF003");
        Assert.Contains(r.Findings, f => f.RuleId == "TRUST-TF010");
    }

    [Fact]
    public async Task MalformedTerraform_NoCrash()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        this is not valid terraform { { {
          source = 
        """);

        // Must not throw.
        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        Assert.NotNull(r);
    }

    [Fact]
    public async Task RequiredFieldsOnAllNewFindings()
    {
        using var fx = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fx.Path, "main.tf"), """
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws" }
          }
        }
        module "m" {
          source = "git::https://example.com/r.git?ref=main"
        }
        resource "aws_db_instance" "db" {
          publicly_accessible = true
        }
        resource "aws_kms_key" "k" {
          enable_key_rotation = false
        }
        resource "aws_s3_bucket_public_access_block" "pab" {
          block_public_acls = false
        }
        """);

        var r = await Analyzer.AnalyzeAsync(new AnalysisContext(fx.Path, fx.Path, AnalysisDepth.Fast), CancellationToken.None);
        foreach (var rid in new[] { "TRUST-TF007", "TRUST-TF008", "TRUST-TF009", "TRUST-TF010", "TRUST-TF011" })
        {
            Assert.All(r.Findings.Where(f => f.RuleId == rid), f =>
            {
                Assert.NotEmpty(f.Evidence);
                Assert.False(string.IsNullOrWhiteSpace(f.Recommendation.Message));
                Assert.False(string.IsNullOrWhiteSpace(f.IdentityKey));
            });
        }
    }
}
