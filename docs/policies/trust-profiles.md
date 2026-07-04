# Trust Profiles

Trust profiles describe the context in which a repository will be used. They are recorded in reports so a scan result can be interpreted with the intended use case in mind.

The current implementation records the selected profile and includes it in JSON and Markdown reports. Scoring and policy evaluation are profile-aware: the same findings may produce different category weights, warnings, violations, blocking risks, and final decisions depending on the selected use case.

## Active Profiles

| Profile | Intended use | Strictness |
| ------- | ------------ | ---------- |
| `Personal` | Experiments, learning projects, and low-impact local tools | Least strict |
| `ProductionDependency` | Libraries, tools, or services considered for production use | Standard production strictness |
| `SecuritySensitiveDependency` | Organization-wide, authentication, cryptography, authorization, secret-handling, or security-control use | Strictest |

Older `EnterpriseDependency`, `CiCdTool`, and `ContainerDependency` inputs are still accepted for compatibility. They are normalized before policy evaluation: enterprise maps to `SecuritySensitiveDependency`, while CI/CD and container aliases map to `ProductionDependency`.

CI/CD and container checks are not separate user profiles. GitHub Actions workflows, pipeline YAML files, Dockerfiles, compose files, and container-related files are detected by analyzers automatically whenever they are present in the repository.

## Built-In Policy Presets

Each active profile resolves to a built-in `TrustPolicy` preset. Presets include minimum overall score, category score thresholds, allowed and denied license handling, maximum vulnerability severity, `SECURITY.md` expectations, unpinned external action handling, and release checksum requirements. Registry allowlists are kept in the policy model for future structured package-source evaluation, but they are not enforced by the current policy evaluator.

Policy presets are intentionally conservative value objects. They do not make analyzers enforce enterprise decisions; analyzers still produce evidence and policy/scoring layers interpret that evidence. Scoring is profile-aware as of `v0.6.0`.

## Policy Evaluation

The policy evaluator reads findings, category scores, the overall score, and the selected built-in policy, then produces violations, warnings, and blocking risks. Evaluation covers:

- known vulnerability findings that exceed the profile maximum,
- unknown license findings according to the profile's unknown-license handling,
- policy-sensitive license findings, with SPDX tags matched against explicit allowed and denied license sets,
- missing `SECURITY.md` when the profile requires it,
- unpinned external GitHub Actions according to profile strictness,
- missing release checksums when the profile requires release checksum evidence,
- overall score and evaluated category scores below the profile minimums,
- findings already marked blocking by analyzers.

Only categories that were actually evaluated by completed analyzer modules are compared with category score thresholds. Unevaluated categories do not create synthetic policy failures.

Policy evaluation does not execute repository code and does not change analyzer behavior.

See [Scan Examples](../examples.md) for end-to-end commands that use each active profile and show when JSON, Markdown, or SARIF output is useful.
