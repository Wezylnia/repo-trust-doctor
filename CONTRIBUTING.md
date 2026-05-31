# Contributing

Thanks for helping build Repository Trust Doctor.

## Development

```powershell
dotnet restore
dotnet build
dotnet test
```

## Contribution Rules

- Keep analyzers isolated and fixture-tested.
- Do not put analyzer logic in CLI, API, or worker projects.
- Do not make analyzers calculate final trust scores.
- Every meaningful finding should include evidence and a practical recommendation.
- Avoid overclaiming for heuristic findings. Use "possible" or "manual review recommended" when confidence is not high.
- Do not execute repository code by default.

## Adding an Analyzer

Start with [docs/analyzer-authoring.md](docs/analyzer-authoring.md), add fixture tests, then document any new rule IDs.

## Licensing of Contributions

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.

You also confirm that you have the right to submit the contribution and that your contribution does not knowingly include code or content you do not have permission to contribute.
