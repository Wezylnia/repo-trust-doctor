# Report Format

Reports are evidence-based summaries of a scan.

The initial report model includes:

- repository path or URL,
- scan mode,
- trust profile,
- started and completed timestamps,
- module statuses,
- findings,
- category scores,
- overall score,
- final decision,
- recommended actions.
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

Reports should be readable in Markdown and deterministic in JSON.

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

Finding fingerprints are lowercase SHA-256 hex strings. They are computed from the rule ID, category, evidence kind, evidence file path, and evidence line number when present. Evidence messages, evidence values, and secret-like content are not fingerprint inputs.

## CLI Export

Reports can be printed to stdout or written to disk:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format markdown --output reports/scan.md
```

When `--output` is provided, the CLI creates the parent directory if needed and writes the selected report format to that file.
If the file already exists, the CLI refuses to overwrite it unless `--force` is supplied.

## CLI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed, no blocking decision |
| `1`  | CLI usage error |
| `2`  | Input/output error |
| `3`  | Scan completed with `AvoidAsProductionDependency` |
