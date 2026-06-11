# repo-trust-doctor Web

Local React trust workbench for scanning GitHub repositories through the `repo-trust-doctor` API backend.

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

Enter repositories as `owner/repo`; the UI sends `https://github.com/owner/repo` to the backend.
