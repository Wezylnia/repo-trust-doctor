# repo-trust-doctor Web

Small React viewer for `repo-trust-doctor` JSON reports. It runs entirely in the browser and does not upload reports to a server.

## Run

```text
npm install
npm run dev
```

The app pins npm resolution to the public npm registry through `.npmrc`. Do not add Azure Artifacts, private registries, or private packages to this project.

Generate a report from the repository root:

```text
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- scan . --format json --output reports/scan.json
```

Open or paste the generated JSON in the web app.
