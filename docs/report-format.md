# Report Format

Reports are evidence-based summaries of a scan.

The initial report model includes:

- repository path or URL,
- scan mode,
- trust profile,
- started and completed timestamps,
- module statuses, timing, coverage/performance metrics, and structured warnings,
- findings,
- category scores,
- overall score,
- final decision,
- recommended actions,
- analyzer artifacts such as dependency inventory when produced.

Each finding includes:

- rule ID,
- title,
- category,
- severity,
- confidence,
- stable fingerprint,
- message,
- evidence,
- recommendation,
- blocking flag.

Reports should be readable in Markdown and deterministic in JSON and SARIF.

Markdown includes a `Top Recommended Actions` section that deduplicates recommendation text and orders representative findings by blocking status, severity, vulnerability/security/release category priority, confidence, rule ID, and first evidence location. The section is advisory only; it does not change scoring, policy decisions, JSON findings, or SARIF output.

Markdown is optimized for human review. When a scan produces more than 100
findings, the Markdown writer renders the first 100 sorted findings and states
how many additional findings were omitted from that view. JSON and SARIF exports
remain complete and include every finding used for scoring, policy evaluation,
and automation.

## API Report Export

`v0.9.5` exposes completed scan reports from the API host:

```text
GET /api/scans/{scanId}/report?format=json
GET /api/scans/{scanId}/report?format=markdown
GET /api/scans/{scanId}/report?format=sarif
```

The API uses the same reporting writers as the CLI. A report request returns `409 Conflict` until the scan has completed.

## Dependency Inventory Artifact

`v0.3.0` added a structured dependency inventory artifact under the stable key `dependency.inventory`. `v0.4.0` adds static package-origin fields and metrics to the same artifact.

The artifact contains:

- manifest records,
- lockfile records,
- package records,
- package source records,
- deterministic string metrics.

Package records include ecosystem, package name, optional version, scope, manifest path, optional lockfile path, direct/transitive marker, pinned marker, prerelease marker, and optional metadata such as npm source kind.

Package source records include ecosystem, source name, redacted source value, source file path, local-source marker, secure-transport marker, and optional metadata.

Markdown reports include a dependency inventory summary when the artifact is present. JSON reports include scan artifacts for machine readers.

The dependency inventory is static-only. It does not fetch registry metadata, resolve latest versions, look up vulnerabilities, or make license claims. Package-origin fields are review signals derived only from manifests and config files already present in the repository.

Markdown output treats finding titles, messages, evidence text, recommendations, decision reasons, target values, and file paths as untrusted text. Inline fields are normalized to one line and escaped so repository-controlled content cannot inject new headings, tables, list items, or raw HTML into a generated Markdown report. Secret-like evidence values remain excluded from SARIF properties and stable fingerprints.

## Deep Code Intelligence Artifacts

`v0.8.0` adds deep code intelligence artifacts. They are produced only by deep scans and remain static/imported-evidence based.

Artifact keys:

- `code.coverage`: imported Cobertura XML or lcov reports, file coverage entries, and coverage metrics.
- `code.criticality`: source files with heuristic criticality scores, line counts, reasons, and first relevant lines.
- `code.public-api`: detected .NET public API symbols, optional baseline path, added symbols, removed symbols, and metrics.

Coverage reports are imported from files already present in the repository workspace. The scanner does not run tests or generate coverage.

Markdown reports include the final scan status, module completion count, analyzer
warnings, failure messages, and skipped-module reasons so a shared report does
not hide incomplete analysis.

SARIF results include every distinct file-backed evidence location for a
finding. Rule defaults use the highest observed severity for that rule in the
scan, independently of finding order, while each result keeps its own severity.
Rule help links target the maintained rule document without guessing a
potentially nonexistent heading anchor.

## Scan Completeness And Scoring

The final trust score distinguishes clean evidence from missing evidence:

- failed, timed-out, cancelled, or unexpectedly skipped modules cap their category score at `70`,
- completed modules with warnings, truncation, unsupported inputs, unresolved package versions, skipped content, or less than 100% reported coverage cap their category score at `90`,
- any incomplete or partial module prevents a `SafeToTry` decision and requires manual review,
- module warnings and metrics remain available in JSON/API reports and are summarized by the React Scan coverage panel.

These caps do not invent vulnerability or security findings. They prevent an absence of evidence from being scored as evidence that a category is clean.

Unexpected analyzer exceptions are reported as module failures with a generic user-facing message. Detailed exception text is not copied into status, progress, or report fields.

## Suppression And Waiver Metadata

`v0.9.5` adds repository suppression support through `.repo-trust.json` at the
repository root. Suppressed findings remain visible in all report formats, are
marked with a `Suppression` property containing the suppression reason, owner,
and optional expiration date. Active suppressions are excluded from score
penalties; expired suppressions are ignored.

JSON reports include suppression metadata on each finding. Markdown reports
separate active and suppressed findings into distinct sections. SARIF output
includes a `repoTrustDoctorSuppressed` property on suppressed results.

Key rules:

- Suppressions require a non-empty reason.
- Expired suppressions are not active.
- Malformed `.repo-trust.json` produces warnings only.
- Raw secrets must not be placed in suppression reasons.

## Structured Evidence Artifacts

`v0.9.5` parses imported SBOM and provenance files into structured artifacts
under the key `release.imported-evidence`. The artifact contains:

- SBOM components with name, version, and package URL (purl),
- provenance subjects with name and digest dictionary,
- file-level metadata including evidence kind and spec version,
- deterministic string metrics.

Structured evidence enables dependency coverage analysis (TRUST-EVI010),
provenance digest checks (TRUST-EVI011), repository identity correlation
(TRUST-EVI012), and conflicting component detection (TRUST-EVI013).

RepoTrustDoctor does not perform cryptographic verification of SBOM or
provenance in this release. These rules are evidence quality and correlation
findings. Absence of imported evidence is not proof that a repository is unsafe.

## GitHub Metadata Artifact

`v0.9.5` collects GitHub repository metadata under the key
`github.repository-metadata`. The artifact contains repository identity,
activity, popularity, release, CI, and branch protection snapshots.

Popularity metrics (stars, forks, watchers) are context-only and never produce
findings. Branch protection data may be unavailable due to API permissions;
unknown data is represented as unknown, not as confirmed absence.

## Trust Diff Format

`v0.9.0` adds trust diff output through the CLI `diff` command. Diff input is two JSON scan reports generated by `scan --format json`.

Diff JSON includes:

- before and after scan snapshots,
- overall score delta,
- decision change marker,
- category score deltas,
- new findings,
- resolved findings,
- worsened findings,
- improved findings,
- unchanged findings.

Markdown and console diff output summarize the same model for human review.

Finding fingerprints are assigned before scoring and policy evaluation, then reused by every report format and trust history. They are lowercase SHA-256 hex strings. The stable identity uses the rule ID, category, normalized title, evidence kind, evidence file path, and structured tags. Finding messages and evidence messages are excluded because they often contain aggregate counts or explanatory wording that can change without changing the underlying risk. Evidence line numbers are also excluded from the base identity so inserting lines above a finding does not turn it into a resolved-plus-new pair. If two findings in the same report remain structurally identical, location and occurrence order are used only to disambiguate that collision. Raw evidence values and secret-like content are never fingerprint inputs.

## CLI Export

Reports can be printed to stdout or written to disk:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format sarif --output reports/scan.sarif
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff reports/before.json reports/after.json --format markdown --output reports/diff.md
```

When `--output` is provided, the CLI creates the parent directory if needed and writes the selected report format to that file.
If the file already exists, the CLI refuses to overwrite it unless `--force` is supplied.

## SARIF Export

SARIF output uses SARIF `2.1.0` and is generated from the same `RepositoryScan` model as JSON and Markdown reports.

- `Finding.RuleId` maps to SARIF rule and result IDs.
- Critical and High findings map to `error`; Medium and Low map to `warning`; Info maps to `note`.
- Stable finding fingerprints map to `partialFingerprints.repoTrustDoctorFingerprint`.
- Repository-relative evidence file paths map to SARIF locations when available.
- Raw evidence values are not written to SARIF.

## CLI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed, no blocking decision |
| `1`  | CLI usage error |
| `2`  | Input/output error |
| `3`  | Scan completed with `AvoidAsProductionDependency` |
| `4`  | Configured CI gate failed |
