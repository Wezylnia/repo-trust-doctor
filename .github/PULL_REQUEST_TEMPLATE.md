## Summary

<!-- What changed, and why? Link the issue this PR closes. -->

- Closes #

## Change Type

- [ ] Analyzer rule or analyzer behavior
- [ ] Reporting or CLI behavior
- [ ] Tests or fixtures
- [ ] Documentation
- [ ] GitHub workflow or repository maintenance
- [ ] Refactor with no intended behavior change

## Verification

- [ ] `dotnet build RepoTrustDoctor.slnx --no-restore`
- [ ] `dotnet test RepoTrustDoctor.slnx --no-build`
- [ ] Local CLI scan, if analyzer/reporting/CLI behavior changed:
	`dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format console`

## Safety Checklist

- [ ] This change does not execute scanned repository code, package managers, build scripts, Docker builds, or install scripts by default.
- [ ] Repository paths in evidence are repository-relative.
- [ ] Possible secrets are redacted from evidence, reports, logs, snapshots, and tests.
- [ ] Network access, if added, is allowlisted, HTTPS-only, bounded by timeout and response size, and covered by tests.

## Analyzer Checklist

- [ ] New or changed findings include rule metadata.
- [ ] Findings include evidence and a practical recommendation.
- [ ] False-positive-prone findings use appropriate confidence and cautious wording.
- [ ] Positive and negative fixture tests were added or updated.
- [ ] Public rule docs were added or updated under `docs/rules/`.

## Notes For Reviewers

<!-- Anything reviewers should pay special attention to? -->
