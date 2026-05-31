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

## Current Policy Behavior

All profiles currently use the same scoring thresholds and final decision logic. This keeps the first policy model conservative and predictable while analyzers and evidence quality are still expanding.

Future policy work may make profile-specific decisions, for example by treating CI/CD token exposure as more severe for `CiCdTool` or dependency provenance gaps as more severe for `EnterpriseDependency`. Any such change should update scorer tests, report documentation, and release notes together.
