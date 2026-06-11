# Web UI

The web UI is a local-first React trust workbench. Its primary flow is to start a GitHub repository scan through the local API backend, poll scan status, fetch the completed report, and show the result directly in the report workspace.

## Scope

- starts GitHub repository scans through the local API backend,
- polls scan status until completion,
- opens the completed report automatically,
- shows overall score, decision, metadata, severity totals, module status, and dependency inventory totals,
- supports finding search, severity filtering, category filtering, and evidence inspection,
- does not expose raw JSON import/export in the React UI.

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

The React app uses `http://localhost:5000` as the local scan service. Users do not choose this as a scan target; they enter a GitHub repository path such as `owner/repo`, which the UI sends to the backend as `https://github.com/owner/repo`.

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
- direct links from findings to report sections,
- backend-backed comparison between two completed scans.
