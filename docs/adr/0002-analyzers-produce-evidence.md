# ADR 0002: Analyzers Produce Evidence

Status: Accepted

## Context

The platform combines multiple analyzer modules, scoring, policies, and report writers. Mixing detection, scoring, and policy decisions inside analyzers would make results harder to explain and harder to tune.

## Decision

Analyzers emit structured findings with rule IDs, severity, confidence, evidence, and recommendations. Scoring and policy layers interpret those findings separately.

## Consequences

Analyzer output stays testable and explainable. Future policy profiles can change interpretation without rewriting analyzer detection logic, but analyzer authors must provide enough evidence for downstream reporting.
