# Contributing

Thanks for helping build Repository Trust Doctor.

RepoTrustDoctor is early, modular, and friendly to focused pull requests. The best contributions are small, evidence-based improvements with tests and clear safety boundaries.

## Find Something To Work On

Start with the contributor-ready issue queue:

- [good first issue](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
- [help wanted](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22)
- [contributor-ready](https://github.com/Wezylnia/repo-trust-doctor/issues?q=is%3Aissue%20is%3Aopen%20label%3Acontributor-ready)

If you want to work on an issue, leave a short comment with your intended approach. A maintainer can confirm scope before you spend much time on it. Please keep one pull request focused on one issue when possible.

Good first contributions include:

- small dependency inventory parser improvements,
- synthetic analyzer fixtures,
- report formatting improvements,
- rule documentation examples,
- focused tests for existing analyzer behavior.

## Development

```powershell
dotnet restore
dotnet build RepoTrustDoctor.slnx --no-restore
dotnet test RepoTrustDoctor.slnx --no-build
```

Run a local CLI smoke test when changing analyzers, orchestration, reporting, CLI behavior, workflows, or policy behavior:

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Cli/RepoTrustDoctor.Cli.csproj -- scan . --format console
```

The solution currently targets .NET 10. Preview SDK warnings are expected while .NET 10 is still preview-era tooling.

## Contribution Rules

- Keep analyzers isolated and fixture-tested.
- Do not put analyzer logic in CLI, API, or worker projects.
- Do not make analyzers calculate final trust scores.
- Every meaningful finding should include evidence and a practical recommendation.
- Avoid overclaiming for heuristic findings. Use "possible" or "manual review recommended" when confidence is not high.
- Do not execute repository code by default.
- Do not run package managers, build scripts, install scripts, Docker builds, or repository tests for scanned repositories.
- Treat repository files, package metadata, URLs, paths, and report strings as untrusted input.
- Redact possible secrets before they reach findings, reports, logs, snapshots, or documentation.
- Keep evidence paths repository-relative.

## Adding an Analyzer

Start with [docs/analyzer-authoring.md](docs/analyzer-authoring.md), add fixture tests, then document any new rule IDs.

Analyzer pull requests should normally include:

- rule metadata in the analyzer,
- positive and negative fixture tests,
- public rule documentation under [docs/rules](docs/rules/README.md),
- severity and confidence choices that are tested or clearly justified,
- recommendations that tell users how to reduce the risk.

Analyzer-to-analyzer communication should happen through artifacts, not direct calls to another analyzer implementation.

## Pull Request Expectations

Before opening a pull request:

1. Keep the change small enough to review comfortably.
2. Link the issue in the pull request body.
3. Fill out the safety checklist.
4. Run build and tests locally.
5. Update docs when behavior, rules, CLI output, or report format changes.

Pull requests to `main` run build/test, CodeQL, and a RepoTrustDoctor self-scan. Non-admin contributors need review before merge.

## Communication

Use [GitHub Discussions](https://github.com/Wezylnia/repo-trust-doctor/discussions) for questions, design sketches, and help choosing an issue. Use issues for actionable bugs, tasks, analyzer rule proposals, and documentation improvements.

Please use [private vulnerability reporting](https://github.com/Wezylnia/repo-trust-doctor/security/advisories/new) for confirmed vulnerabilities instead of public issues.

## Licensing of Contributions

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.

You also confirm that you have the right to submit the contribution and that your contribution does not knowingly include code or content you do not have permission to contribute.
