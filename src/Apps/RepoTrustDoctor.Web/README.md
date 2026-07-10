# repo-trust-doctor Web

Local React workbench for making an evidence-backed adoption decision about a public GitHub repository. It turns an `owner/repo` input into a profile-aware recommendation, prioritized next steps, scan coverage, and exportable evidence.

## Run

```text
npm install
npm run dev
```

The app pins npm resolution to the public npm registry through `.npmrc`. Do not add Azure Artifacts, private registries, or private packages to this project.

Run the API backend in another shell:

```text
dotnet run --project ../RepoTrustDoctor.Api --urls http://localhost:5000
```

Enter repositories as `owner/repo`; the UI sends `https://github.com/owner/repo` to the backend. The default `Standard` depth is intended for normal adoption decisions; choose `Deep` when the decision needs code-intelligence evidence.

Use **Explore a demo report** to review the complete decision flow without starting the API. During a live scan, the workbench polls module progress and shows the current analysis stage. Completed reports keep adoption context, recommendation, and next steps in one summary band; detailed scores, coverage, technical metadata, filters, and grouped findings use the full page width below it.

## Validate

```text
npm ci
npm test
npm run build
npm run test:visual
```

Playwright snapshots cover the scan workspace and desktop/mobile report layouts. Use `npm run test:visual:update` only after intentionally reviewing a visual change. The repository CI runs all four checks alongside the .NET build, tests, and CLI smoke scan.
