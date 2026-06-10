# Trust Profiles

Trust profiles describe the context in which a repository will be used. They are recorded in reports so a scan result can be interpreted with the intended use case in mind.

The current implementation records the selected profile and includes it in JSON and Markdown reports. Scoring is currently profile-neutral: the same findings produce the same score and final decision for every profile until policy thresholds are implemented.

## Built-In Profiles

| Profile | Intended use | Future strictness |
| ------- | ------------ | ----------------- |
| `Personal` | Personal experiments, learning projects, and low-impact local tools | Least strict |
| `ProductionDependency` | Libraries, tools, or services considered for production dependency use | Standard production strictness |
| `EnterpriseDependency` | Dependencies considered for managed organization-wide use | Stricter than production dependency |
| `CiCdTool` | Tools or actions that run inside CI/CD systems and may receive repository tokens or build secrets | Strict on workflow, token, and release provenance risk |
| `SecuritySensitiveDependency` | Dependencies used in authentication, cryptography, authorization, secret handling, or security controls | Strictest on security and maintainer risk |
| `ContainerDependency` | Base images, Dockerfiles, or containerized tools used as runtime or build dependencies | Strict on image provenance, pinning, and build surface |

## Built-In Policy Presets

Each profile resolves to a built-in `TrustPolicy` preset. Presets include minimum overall score, category score thresholds, allowed and denied license placeholders, maximum vulnerability severity, SECURITY.md expectations, unpinned action handling, release checksum requirements, and allowed registry placeholders.

Policy presets are intentionally conservative value objects. They do not make analyzers enforce enterprise decisions; analyzers still produce evidence and policy/scoring layers interpret that evidence.
