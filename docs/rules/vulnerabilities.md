# Vulnerability Rules

## TRUST-VULN001: Direct Dependency Has a Known Vulnerability

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects OSV advisories that match a direct dependency name and exact resolved version. Dependencies declared only in common test, fixture, documentation, example, or playground manifests are skipped to avoid reporting vulnerabilities in intentionally fake package fixtures. Repeated declarations of the same ecosystem, package, and version are queried once and reported once per advisory. Version ranges such as `^1.2.3` are not presented to OSV as if they were installed versions; they remain visible in coverage metrics until a lockfile or other exact version source is available.

Why it matters: direct vulnerable dependencies are usually easier to prioritize because the repository explicitly chose the dependency.

Recommendation: review the advisory and update the dependency to a fixed version when available.

## TRUST-VULN002: Transitive Dependency Has a Known Vulnerability

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects OSV advisories that match a transitive dependency name and exact resolved version when transitive package data is available. Dependencies declared only in common test, fixture, documentation, example, or playground manifests are skipped. When the same vulnerable package appears both directly and transitively, the direct dependency finding takes precedence.

Why it matters: transitive vulnerabilities may still matter, but reachability and upgrade path usually require additional review.

Recommendation: review whether the vulnerable transitive package is reachable and update the dependency chain where possible.

## TRUST-VULN003: Vulnerable Dependency Has a Known Fixed Version

- Category: Dependencies
- Default severity: Info
- Default confidence: High

Detects advisory metadata that lists one or more fixed versions.

Why it matters: fixed-version evidence makes remediation more actionable.

Recommendation: upgrade to a fixed version listed by the advisory when compatible.

## Lookup Coverage And Failure Behavior

Vulnerability lookup has no fixed package-count cutoff. Ready ecosystems are queried from the local SQLite OSV index. Exact affected-version lists and `SEMVER` ranges are evaluated locally. Ecosystem-specific or Git ranges that cannot be evaluated conservatively use the online OSV fallback instead of being treated as unaffected.

When local data is unavailable, supported packages are sent to OSV in batches of 100 with at most four batches in flight. OSV pagination is followed per package, and full advisory records are fetched with bounded concurrency.

The analyzer has a 55-second soft lookup budget inside a 60-second module timeout. If the budget expires, findings from completed batches are preserved and the report records completed and incomplete package counts. Failed batches are not treated as clean results. Confirmed advisory matches remain visible even when advisory details cannot be loaded, but use conservative severity and include a warning.

The report exposes candidate, unpinned, supported, unsupported, completed, incomplete, local, and online vulnerability lookup counts. This distinguishes "no vulnerability was found" from "this dependency could not be checked" and shows how much network fallback was required.

Official OSV ecosystem archives and incremental modified-advisory indexes can be refreshed by the optional production background service. See [Local Dependency Intelligence](../local-intelligence.md).
