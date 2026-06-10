# Release Checklist

Use this checklist before publishing a Repository Trust Doctor release.

## Scope

- Confirm the release does not implement contributor-owned GitHub issues unless that work was explicitly pulled back.
- Confirm the release keeps default scanning static-only.
- Confirm release notes describe limitations without implying security certification.

## Version Metadata

- Update `ProductInfo.Version`.
- Update README current status when the visible milestone changes.
- Add a dated entry to `CHANGELOG.md`.
- Verify `repo-trust-doctor --version` prints the expected version.

## Validation

```powershell
git status --short --branch
dotnet build RepoTrustDoctor.slnx --no-restore
dotnet test RepoTrustDoctor.slnx --no-build
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- --version
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format console
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format json --output artifacts/release-scan.json --force
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- diff artifacts/release-scan.json artifacts/release-scan.json --format console
```

## Security Review

- Do not execute scanned repository code.
- Do not add raw secrets to tests, docs, snapshots, or release notes.
- Verify secret-like evidence remains redacted.
- Verify generated reports use repository-relative paths.
- Verify report overwrite protection still requires `--force`.

## Publish

- Push release commits to `main`.
- Create a release tag such as `v0.4.0`.
- Create a GitHub release with the changelog summary.
- Confirm CI, CodeQL, and required repository checks complete on the pushed commit or release tag.
