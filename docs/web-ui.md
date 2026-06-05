# Web UI

The web UI is a local-first React report viewer for `repo-trust-doctor` JSON output. It is intended to make scan results easier to inspect without changing the scanner execution model.

## Scope

- opens local JSON reports in the browser,
- accepts pasted JSON reports,
- shows score, decision, metadata, severity totals, module status, and dependency inventory totals,
- supports finding search, severity filtering, category filtering, and evidence inspection,
- does not upload repository data or reports.

## Development

```text
cd src/Apps/RepoTrustDoctor.Web
npm install
npm run dev
```

The web app uses the public npm registry only. Its `.npmrc` sets `registry=https://registry.npmjs.org/`; private feeds such as Azure Artifacts must not be added.

Generate a compatible report from the repository root:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json --output reports/scan.json
```

## Build

```text
cd src/Apps/RepoTrustDoctor.Web
npm run build
```
