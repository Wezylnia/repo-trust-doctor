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

## Rule Author Checklist

- [ ] Add rule metadata to the analyzer `Rules` collection.
- [ ] Use a stable rule ID in the `TRUST-{CATEGORY}{NUMBER}` format and avoid reusing an existing ID for different behavior.
- [ ] Document the rule under [docs/rules](rules/README.md) or the relevant rule catalog page, and update [Analyzers & Rules Reference](analyzers-and-rules.md) if the public catalog changes.
- [ ] Choose severity and confidence from directly observable evidence. Keep heuristic detections at `Medium` or `Low` confidence unless the fixture proves a high-signal condition.
- [ ] Add fixture-based analyzer tests for positive, negative, and edge-case behavior. Tests must not require network access, package installation, builds, containers, or external services.
- [ ] Keep analyzer logic static-only unless the analyzer is explicitly designed for a future sandboxed execution mode.
- [ ] Attach evidence that is specific enough for review, with stable paths, line numbers when available, and a recommendation that explains the next action.
- [ ] Verify sensitive evidence is redacted before it reaches findings, reports, logs, or snapshots.
- [ ] Check false-positive risk with at least one realistic non-finding fixture before raising severity or confidence.
- [ ] Verify the analyzer timeout is set and appropriate for the scan depth, and expose warnings or metrics when work is intentionally capped.
- [ ] Confirm JSON, Markdown, and SARIF output remains deterministic if the rule affects report ordering, fingerprints, evidence, or remediation text.
- [ ] Run the focused analyzer tests and the relevant broader test project before opening or merging the change.
