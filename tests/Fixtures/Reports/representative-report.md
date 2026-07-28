# Repository Trust Report

- Target: `fixtures/repository`
- Tool version: `1.0.0`
- Scan mode: `Fast`
- Trust profile: `ProductionDependency`
- Scan status: `Completed`
- Overall score: `42/100`
- Decision: `NeedsManualReview`

## Finding Summary

| Severity | Count |
| -------- | ----- |
| Critical | 1 |
| High     | 0 |
| Medium   | 1 |
| Low      | 0 |
| Info     | 0 |
| **Total**    | **2** |
| Blocking | 1 |

## Decision Reasons
- A blocking security finding requires manual review.
- Workflow permissions should be reduced.

## Modules
- Completion: `2/2` modules completed
- `secrets`: Completed (1 findings)
- `github-actions`: Completed (1 findings)


## Top Recommended Actions
- Rotate the credential and move it to a secret store.
- Reduce workflow permissions to the minimum required.

## Findings

Showing 2 of 2 findings.

### TRUST-SECRET005 - Exposed connection string

- Severity: `Critical`
- Confidence: `High`
- Category: `Security`
- Fingerprint: `aec24d6c416a330ca32a18990fcfa367cdcba6ba5655c0e2b02b42ba432d730c`
- Message: A secret-like connection string was detected and redacted.
- Recommendation: Rotate the credential and move it to a secret store.
- Evidence: The connection string value was redacted before reporting. `src/appsettings.Production.json`

### TRUST-GHA005 - Workflow permissions are too broad

- Severity: `Medium`
- Confidence: `High`
- Category: `CiCd`
- Fingerprint: `2df2212f6934b45d3300ca8fc1aa347a6b56b2b1de48e92a5cb1cdc50b5e1ca7`
- Message: The workflow grants broader permissions than required.
- Recommendation: Reduce workflow permissions to the minimum required.
- Evidence: The workflow grants write permissions. `.github/workflows/ci.yml`
