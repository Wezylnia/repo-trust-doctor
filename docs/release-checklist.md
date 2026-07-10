# Release Checklist

Use this checklist before publishing a Repository Trust Doctor release.

## Scope

- Confirm the release does not implement contributor-owned GitHub issues unless that work was explicitly pulled back.
- Confirm the release keeps default scanning static-only.
- Confirm release notes describe limitations without implying security certification.

## Version Metadata

- Update `ProductInfo.Version`.
- Update `VersionPrefix` in `Directory.Build.props` and the web package version.
- Update README current status when the visible milestone changes.
- Add a dated entry to `CHANGELOG.md`.
- Verify `repo-trust-doctor --version` prints the expected version.
- Verify the intended tag matches every visible product version.

## Validation

```powershell
git status --short --branch
dotnet build RepoTrustDoctor.slnx --no-restore
dotnet test RepoTrustDoctor.slnx --no-build
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- --version
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format console
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format json --output artifacts/release-scan.json --force
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- diff artifacts/release-scan.json artifacts/release-scan.json --format console
dotnet pack src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj --configuration Release --output artifacts/package

cd src/Apps/RepoTrustDoctor.Web
npm ci
npm test
npm run build
npm run test:visual
```

## Security Review

- Do not execute scanned repository code.
- Do not add raw secrets to tests, docs, snapshots, or release notes.
- Verify secret-like evidence remains redacted.
- Verify generated reports use repository-relative paths.
- Verify report overwrite protection still requires `--force`.
- Run `dotnet list RepoTrustDoctor.slnx package --vulnerable --include-transitive` and resolve every reported production vulnerability.

## Publish

- Push the validated release commit to `main`.
- Create and push an annotated tag such as `v1.0.0`.
- Confirm the tag-triggered release workflow creates Windows, Linux, macOS, .NET tool, and checksum artifacts.
- Smoke-test at least one downloaded self-contained archive and the packaged .NET tool.
- Confirm CI, release validation, CodeQL, and required repository checks complete on the release commit or tag.
