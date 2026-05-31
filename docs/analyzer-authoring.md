# Analyzer Authoring Guide

Analyzers are small, isolated modules that inspect repository files or metadata and produce structured evidence.

An analyzer must define:

- stable analyzer ID,
- display name,
- analysis category,
- minimum scan depth,
- execution safety,
- dependencies on artifacts or analyzer IDs,
- cancellation-aware `AnalyzeAsync` implementation.

Analyzers should produce:

- findings with rule IDs,
- evidence,
- recommendations,
- reusable artifacts when useful,
- warnings or failure metadata when analysis is incomplete.

Analyzers must not:

- calculate final trust scores,
- make profile-specific approval decisions,
- call another analyzer implementation directly,
- execute repository code unless explicitly designed for a future sandboxed mode.

Rule IDs use this shape:

```text
TRUST-{CATEGORY}{NUMBER}
```

Examples:

```text
TRUST-REPO001
TRUST-GHA001
TRUST-SECRET001
TRUST-DOCKER001
```

Document new rules under [docs/rules](rules/README.md) when adding or changing analyzer output.
