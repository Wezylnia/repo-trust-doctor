# Release Rules

## TRUST-REL001: Changelog Does Not Mention Detected Package Version

- Category: Releases
- Default severity: Low
- Default confidence: Medium

Detects package version metadata that is not mentioned in the changelog.

Why it matters: users need release notes that correspond to published package versions.

Recommendation: add release notes for the package version in `CHANGELOG.md`.

## TRUST-REL002: Release Artifact Lacks Checksum Evidence

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects local release artifacts under common release output directories without nearby checksum files.

Why it matters: checksums help users verify downloaded artifact integrity.

Recommendation: publish SHA-256 or SHA-512 checksums next to release artifacts.

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

## TRUST-REL005: Release Workflow Lacks Integrity Evidence Steps

- Category: Releases
- Default severity: Medium
- Default confidence: Medium

Detects release workflows that appear to publish packages or artifacts without checksum, SBOM, provenance, or attestation steps.

Why it matters: release automation should make artifact integrity evidence easy for users to find.

Recommendation: add checksum, SBOM, provenance, or attestation generation to release workflows.
