# Release Rules

## TRUST-REL001: Changelog Does Not Mention Detected Package Version

- Category: Releases
- Default severity: Low
- Default confidence: Medium

Detects package version metadata that is not mentioned in the changelog.

Why it matters: users need release notes that correspond to published package versions.

Recommendation: add release notes for the package version in `CHANGELOG.md`.

Noise control: nested packages use package-directory changelogs first. A root
changelog is used for a nested package only when it contains a package-specific
heading/section, or when a fixed-version Lerna release model is explicitly
configured. Lerna package include and exclude patterns bound that shared
release scope. Equal package versions alone are not treated as proof of a
shared release model. Independent-version workspaces are not compared with an
unrelated global changelog version. Private, fixture, example, test, and
documentation package manifests are ignored.

## TRUST-REL002: Release Artifact Lacks Checksum Evidence

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects local release artifacts under common release output directories without nearby checksum files.

Why it matters: checksums help users verify downloaded artifact integrity.

Recommendation: publish SHA-256 or SHA-512 checksums next to release artifacts.

Noise control: detached signatures such as `.sig` files are preserved as separate integrity evidence and do not count as SHA-256 or SHA-512 checksum files.

Policy impact: profiles that require release checksum evidence, such as `SecuritySensitiveDependency`, treat this finding as a blocking policy violation.

## TRUST-REL003: Release Artifact Lacks SBOM or Provenance Evidence

- Category: Releases
- Default severity: Low
- Default confidence: Medium

Detects local release artifacts without nearby SBOM, provenance, or attestation evidence.

Why it matters: SBOM and provenance evidence improve supply-chain review and auditability.

Recommendation: publish SBOM or provenance/attestation evidence for release artifacts.

## TRUST-REL004: Package Version Does Not Match Latest Changelog Version

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects a mismatch between package version metadata and the latest version heading in the changelog.

Why it matters: version drift can confuse users and weaken release traceability.

Recommendation: keep package version metadata and release notes aligned.

Noise control: `pyproject.toml` versions are read only from `[project]` and `[tool.poetry]`; version fields belonging to linters, build plugins, or other tools are ignored.

Noise control: package-local release notes take precedence. Central root release
notes are associated with nested packages through package names, manifest
directories, or explicit fixed-version workspace evidence; another package's
version entry does not satisfy the current package. Monorepo helper packages,
fixtures, examples, and private packages remain excluded.

## Evidence Import Rules

### TRUST-EVI001: SBOM evidence found in repository

- Category: Releases
- Default severity: Info
- Default confidence: High

Detects recognized SBOM files in the repository. Positive SBOM evidence is emitted only after CycloneDX or SPDX JSON structure is recognized.

Why it matters: SBOMs help track dependencies. Positive signal, not a risk.

Recommendation: ensure the SBOM is up-to-date and covers all components.

### TRUST-EVI003: Provenance evidence found in repository

- Category: Releases
- Default severity: Info
- Default confidence: High

Detects parseable provenance or attestation files in the repository. Positive provenance evidence is emitted only after JSON or JSONL content is parsed successfully.

Why it matters: provenance helps verify build integrity. Positive signal, not a risk.

Recommendation: ensure provenance evidence covers all release artifacts.

### TRUST-EVI004: SBOM evidence file is not parseable

- Category: Releases
- Default severity: Medium
- Default confidence: High

Detects SBOM JSON files that cannot be parsed as valid JSON.

Why it matters: corrupt evidence cannot be trusted.

Recommendation: ensure SBOM files are valid JSON.

### TRUST-EVI005: SBOM evidence appears empty

- Category: Releases
- Default severity: Low
- Default confidence: Medium

Detects SBOM JSON files with empty `components` or `packages` arrays.

Why it matters: an empty SBOM provides no dependency visibility.

Recommendation: regenerate the SBOM to include all components.

### TRUST-EVI006: Provenance evidence file is not parseable

- Category: Releases
- Default severity: Medium
- Default confidence: High

Detects provenance JSON or JSONL files that cannot be parsed. Invalid provenance files do not also count as positive provenance evidence.

Why it matters: corrupt provenance evidence cannot verify build integrity.

Recommendation: ensure provenance files are valid JSON.

### TRUST-EVI007: SBOM appears potentially incomplete

- Category: Releases
- Default severity: Low
- Default confidence: Medium

Detects SBOM files with very few components compared with the direct dependency inventory available to the scan.

Why it matters: a very small SBOM may have been generated from only part of a monorepo or from the wrong build target.

Recommendation: regenerate the SBOM from the current build graph and confirm it covers the packages being released.

### TRUST-EVI008: SBOM package URL is malformed

- Category: Releases
- Default severity: Low
- Default confidence: High

Detects malformed SBOM package URLs, including `purl` values that do not use the `pkg:` scheme or that omit the required package type/name structure.

Why it matters: malformed package URLs make it harder to correlate SBOM components with advisory and registry metadata.

Recommendation: fix malformed package URLs in the SBOM and regenerate the evidence from the package manager or build tool.

## TRUST-REL005: Release Workflow Lacks Integrity Evidence Steps

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects release workflows that appear to publish packages or artifacts without checksum, SBOM, provenance, or attestation steps.

Why it matters: release automation should make artifact integrity evidence easy for users to find.

Recommendation: add checksum, SBOM, provenance, or attestation generation to release workflows.

Noise control: YAML comments are removed before publish and integrity evidence patterns are evaluated, so TODO comments do not satisfy the rule or create a false release signal.

## TRUST-EVI010: SBOM Does Not Cover Direct Dependency Inventory

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects when the imported SBOM appears to cover fewer than 70% of the direct
dependencies detected by the dependency inventory. This rule runs only when at
least 10 direct dependencies have correlatable identities and at least one SBOM
component has a valid package URL.

Why it matters: an SBOM that covers only a fraction of direct dependencies may
have been generated from a partial build graph and may not provide complete
supply-chain visibility.

Recommendation: regenerate the SBOM from the current build graph to include all
direct dependencies. The message uses cautious wording and does not claim the
SBOM is invalid or malicious.

## TRUST-EVI011: Provenance Subject Does Not Contain a Digest

- Category: Releases
- Default severity: Medium
- Default confidence: High

Detects provenance subjects that do not include a SHA-256 or SHA-512 digest key.
This rule does not verify digest values and does not claim artifact tampering.

Why it matters: provenance without a cryptographic digest does not provide
meaningful artifact integrity evidence.

Recommendation: ensure provenance generation includes SHA-256 or SHA-512 digests
for all subjects.

## TRUST-EVI012: Provenance Repository Identity Differs From Target

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects when provenance metadata references a different repository than the
scanned target. If the repository identity cannot be determined, this rule is
not triggered.

Why it matters: provenance generated for a different repository is not useful
for verifying the current repository's artifacts.

Recommendation: ensure provenance was generated for the current repository.

## TRUST-EVI013: Evidence Contains Conflicting Component Identities

- Category: Releases
- Default severity: Low
- Default confidence: High

Detects when the same normalized package URL appears with conflicting component
versions within a single imported evidence file. One aggregate finding is
emitted per SBOM file.

Why it matters: conflicting component versions in imported evidence may indicate
a generation error or a merge artifact.

Recommendation: review and reconcile conflicting component versions in imported
evidence. RepoTrustDoctor does not perform cryptographic verification of SBOM or
provenance in this release; these rules are evidence quality and correlation
findings.
