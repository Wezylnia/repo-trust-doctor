# Web UI

The web UI is a local-first React trust workbench. Its primary flow is to start a scan through the local API backend, poll scan status, fetch the completed report, and show the result directly in the report workspace.

Opening a saved JSON report remains supported for CI artifacts, shared reports, and offline review, but it is not the primary product flow.

## Scope

- starts repository scans through the local API backend,
- polls scan status until completion,
- opens the completed report automatically,
- opens local saved JSON reports in the browser,
- accepts pasted saved JSON reports,
- shows score, decision, metadata, severity totals, module status, and dependency inventory totals,
- supports finding search, severity filtering, category filtering, and evidence inspection,
- does not upload reports to a third-party service.

## Development

```text
cd src/Apps/RepoTrustDoctor.Web
npm install
npm run dev
```

The web app uses the public npm registry only. Its `.npmrc` sets `registry=https://registry.npmjs.org/`; private feeds such as Azure Artifacts must not be added.

Run the local API backend:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Api --urls http://localhost:5000
```

The scan target can be either an absolute local repository path accessible to the backend process or a public HTTP(S) Git repository URL.

Saved report fallback:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json --output reports/scan.json
```

## Validate

```text
cd src/Apps/RepoTrustDoctor.Web
npm run build
npm test
```

## v1.1.0 Direction

The next React/backend milestone should keep the same primary flow and deepen it:

- richer live progress by module while scans are running,
- API health and compatibility detection in the web app,
- report history backed by persistence rather than browser-only state,
- scan cancellation and retry feedback,
- direct links from findings to report sections and saved exports,
- backend-backed comparison between two completed scans.
