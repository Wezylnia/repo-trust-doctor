# Trust History and Diff

`v0.9.0` adds the first history and comparison layer. It is intentionally file-based and source-safe: snapshots are derived from scan reports and do not store raw repository source files.

## Snapshot Model

`TrustSnapshotFactory` converts a `RepositoryScan` into a compact `ScanSnapshot` containing:

- scan identity, target, depth, trust profile, tool version, and completion time,
- overall score and final decision,
- category scores,
- finding summary,
- finding snapshots with fingerprint, rule ID, title, category, severity, blocking flag, and primary file path.

Finding fingerprints are computed with the same stable report fingerprinter used by JSON, Markdown, and SARIF reports.

Line numbers are treated as location metadata rather than primary finding
identity. A finding that moves within the same file remains matched when its
rule and redacted structural evidence are unchanged. Structurally identical
repeated findings in one report receive collision-safe unique fingerprints.

## Trust Diff

The CLI can compare two JSON scan reports:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff before.json after.json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff before.json after.json --format markdown --output reports/diff.md
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- diff before.json after.json --format json --output reports/diff.json --force
```

Diff output includes:

- overall score delta,
- decision change,
- comparability state (`Direct`, `Partial`, or `DifferentTarget`) with reasons when score deltas are not directly comparable,
- category score deltas for comparable categories,
- newly evaluated or no-longer-evaluated category states when a category exists in only one report,
- new findings,
- resolved findings,
- worsened findings,
- improved findings,
- unchanged findings.

Severity or blocking changes are tracked when the same fingerprint appears in both scans.

## Repository Comparison

`RepositoryComparisonEngine` compares multiple snapshots and sorts repositories by lowest trust score first. Each entry includes the target, score, decision, finding summary, and top high/blocking risks.

This is designed for dependency selection workflows where a user wants to compare candidate repositories before adopting one.

## Regression Alerts

`TrustRegressionDetector` converts a diff into alerts for:

- score drops,
- worsened final decisions,
- new blocking findings,
- new high-severity findings.

`ScheduledScanDefinition` captures the first monitoring model: target, depth, profile, cron expression, score-drop threshold, and new-finding alert severity. It is a contract for future worker/API scheduling; `v0.9.0` does not add notification providers or a hosted dashboard.

## Safety Boundaries

- Scan snapshots are derived from reports and avoid raw repository source storage.
- The diff command reads local JSON reports; it does not clone repositories or execute code.
- Regression alerts are local model outputs and do not send notifications by default.
