# Vulnerability Rules

## TRUST-VULN001: Direct Dependency Has a Known Vulnerability

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects OSV advisories that match a direct dependency name and version.

Why it matters: direct vulnerable dependencies are usually easier to prioritize because the repository explicitly chose the dependency.

Recommendation: review the advisory and update the dependency to a fixed version when available.

## TRUST-VULN002: Transitive Dependency Has a Known Vulnerability

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects OSV advisories that match a transitive dependency name and version when transitive package data is available.

Why it matters: transitive vulnerabilities may still matter, but reachability and upgrade path usually require additional review.

Recommendation: review whether the vulnerable transitive package is reachable and update the dependency chain where possible.

## TRUST-VULN003: Vulnerable Dependency Has a Known Fixed Version

- Category: Dependencies
- Default severity: Info
- Default confidence: High

Detects advisory metadata that lists one or more fixed versions.

Why it matters: fixed-version evidence makes remediation more actionable.

Recommendation: upgrade to a fixed version listed by the advisory when compatible.
