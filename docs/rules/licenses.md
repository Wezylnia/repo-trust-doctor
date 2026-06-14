# License Rules

## TRUST-LIC001: Dependency License Is Unknown

- Category: Licenses
- Default severity: Low
- Default confidence: Medium

Detects package metadata with an unrecognized short license expression.

Why it matters: unknown license metadata may require manual legal or compliance review before production use.

Recommendation: manually review the package license before production use.

## TRUST-LIC002: Dependency Uses a Policy-Sensitive License

- Category: Licenses
- Default severity: Medium
- Default confidence: Medium

Detects common copyleft license families such as GPL, LGPL, and AGPL in package metadata. Expressions where a copyleft license is required, such as `MIT AND GPL-3.0-only`, are treated as policy-sensitive. Expressions with a clear permissive alternative, such as `MIT OR GPL-3.0-only`, are not reported by this rule.

Why it matters: copyleft licenses may carry obligations that depend on usage context. RepoTrustDoctor reports this as a review signal, not a legal conclusion.

Recommendation: review license obligations with the appropriate legal or compliance process.

## TRUST-LIC003: Package License Metadata Is Missing

- Category: Licenses
- Default severity: Low
- Default confidence: High

Detects package metadata that does not include a license expression.

Why it matters: missing license metadata makes dependency approval and audit evidence weaker.

Recommendation: prefer packages with clear license metadata or document the manual review result.
