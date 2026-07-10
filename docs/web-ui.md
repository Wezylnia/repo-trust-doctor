# Web UI

The web UI is a local-first React trust workbench. Its primary flow is to start a GitHub repository scan through the local API backend, poll scan status, fetch the completed report, and show the result directly in the report workspace.

## Scope

- starts GitHub repository scans through the local API backend,
- polls scan status until completion,
- shows live lifecycle and module progress while a scan is running,
- opens the completed report automatically,
- offers a built-in demo report without requiring the API,
- shows plain-language scan depth and profile labels,
- includes a side guide for choosing one of three scan profiles,
- shows a short product introduction before the scan form,
- shows overall score, area scores, decision, metadata, severity totals, module status, and dependency inventory totals,
- formats report enum values into readable labels instead of exposing API casing,
- shows dependency metadata, vulnerability advisory, and secret-content scan coverage, including partial results and unsupported inputs,
- surfaces analyzer timeouts, failures, and warnings instead of presenting partial scans as complete,
- adds explanatory finding detail text alongside evidence and recommendations,
- supports finding search, severity filtering, category filtering, repeated-finding grouping, actionable-only review, and evidence inspection,
- keeps technical metadata and dependency inventory in a collapsible details panel,
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
npm run test:visual
```

## Next React Direction

After `v1.0.0`, the React/backend scan experience keeps the same primary flow and deepens it through:

- API health and compatibility detection in the web app,
- report history backed by persistence rather than browser-only state,
- direct links from findings to report sections,
- backend-backed comparison between two completed scans.
