# Security Review Checklist

Use this checklist for changes that touch repository intake, analysis, reporting, workflows, or hosted execution.

## Input Handling

- [ ] Treat repository contents, paths, manifests, workflows, and config files as untrusted input.
- [ ] Apply explicit size limits and timeouts before reading large files or remote responses.
- [ ] Prefer structured parsers for known formats instead of ad hoc string parsing when practical.

## URL Handling

- [ ] Reject repository URLs with credentials, fragments, or unsupported schemes.
- [ ] Allow only expected HTTP(S) Git clone targets unless a stricter policy is added.
- [ ] Avoid logging tokens, credentials, or sensitive URL components.

## File Traversal

- [ ] Normalize and validate paths before opening files from repository input.
- [ ] Keep reads inside the prepared repository workspace.
- [ ] Skip generated, dependency, and private planning directories when appropriate.

## Archive Or Upload Intake

- [ ] Define explicit upload policy before accepting archive or API-based file intake.
- [ ] Enforce file count, total size, per-file size, extraction depth, and timeout limits.
- [ ] Reject path traversal entries, absolute paths, symlinks, and dangerous archive metadata.

## Temporary Workspace Cleanup

- [ ] Create temporary clone or extraction directories under controlled locations.
- [ ] Clean up temporary workspaces after success, failure, cancellation, and timeout.
- [ ] Do not recurse into submodules or execute clone hooks during default scans.

## Secret Redaction

- [ ] Redact secret-like values before storing evidence, logs, reports, or test snapshots.
- [ ] Do not include raw secret values in fingerprints, cache keys, telemetry, or SARIF properties.
- [ ] Keep examples synthetic and clearly non-functional.

## Workflow Permissions

- [ ] Set least-privilege `permissions` at workflow or job scope.
- [ ] Avoid granting write permissions to pull request jobs unless required and reviewed.
- [ ] Prefer read-only tokens for analysis jobs.

## Action Pinning

- [ ] Pin external GitHub Actions to full commit SHAs.
- [ ] Review action updates before changing pinned SHAs.
- [ ] Keep Dependabot or equivalent update visibility for pinned actions.

## Report Output Safety

- [ ] Refuse to overwrite report files unless `--force` or an equivalent explicit option is used.
- [ ] Keep machine-readable output deterministic where alert tracking depends on it.
- [ ] Avoid embedding raw untrusted HTML, scripts, or secret values in generated reports.

## No Execution Of Untrusted Code

- [ ] Do not run build scripts, tests, package lifecycle hooks, or repository tooling by default.
- [ ] Any future execution mode must be explicit, isolated, resource-limited, and documented.
- [ ] Prefer lower-confidence static findings over unsafe execution.

## Suppression Configuration (.repo-trust.json)

- [ ] Suppressions do not delete findings; they remain visible in all report formats.
- [ ] Suppressions require a non-empty reason.
- [ ] Expired suppressions are ignored.
- [ ] Raw secrets must not be placed in suppression reasons.
- [ ] Malformed .repo-trust.json produces warnings only, never crashes the scan.
- [ ] Suppression config is read only from the repository root; no path traversal.
