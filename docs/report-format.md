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

Each finding includes:

- rule ID,
- title,
- category,
- severity,
- confidence,
- message,
- evidence,
- recommendation,
- blocking flag.

Reports should be readable in Markdown and deterministic in JSON.

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
