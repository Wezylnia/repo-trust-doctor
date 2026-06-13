# Terraform Rules

## TRUST-TF001: Public Ingress from the Internet

- Category: Infrastructure
- Default severity: High
- Default confidence: Medium

Detects security group rules allowing ingress from `0.0.0.0/0` or `::/0`.

Why it matters: open ingress exposes services to the entire internet, increasing attack surface.

Recommendation: restrict ingress to specific CIDR ranges.

## TRUST-TF002: Wildcard IAM Action and Resource

- Category: Infrastructure
- Default severity: High
- Default confidence: Medium

Detects IAM policies with both `Action = "*"` and `Resource = "*"`.

Why it matters: wildcard IAM policies grant unrestricted access to all resources.

Recommendation: limit actions and resources to the minimum required.

## TRUST-TF003: S3 Bucket Public ACL

- Category: Infrastructure
- Default severity: High
- Default confidence: High

Detects `acl = "public-read"` or `acl = "public-read-write"` on S3 buckets.

Why it matters: public ACLs expose bucket contents to anyone on the internet.

Recommendation: use private ACL and grant access through bucket policies.

## TRUST-TF004: S3 Bucket Encryption Not Visible

- Category: Infrastructure
- Default severity: Medium
- Default confidence: Low

Detects S3 buckets without visible `server_side_encryption_configuration`.

Why it matters: unencrypted buckets may expose data at rest. This is a heuristic check.

Recommendation: enable default S3 server-side encryption.

## TRUST-TF005: Provider Version Constraint Missing

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects `required_providers` entries without a `version` constraint.

Why it matters: unversioned providers can drift and break infrastructure.

Recommendation: add version constraints to all required providers.

Fixture, sample, example, and Terraform testdata paths are skipped for this rule family so provider snippets used by Terraform's own tests or documentation are not scored as production infrastructure.

## TRUST-TF006: S3 Backend Lacks Encryption

- Category: Infrastructure
- Default severity: Low
- Default confidence: Medium

Detects `backend "s3"` blocks without `encrypt = true`.

Why it matters: unencrypted state files may expose sensitive infrastructure details.

Recommendation: set `encrypt = true` in S3 backend configuration.
