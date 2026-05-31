# ADR 0003: Admin Bypass For Maintainers

Status: Accepted

## Context

The public repository uses protected `main`, required reviews for non-admin contributors, required CI checks, CodeQL, OSSF Scorecard, Dependabot, and Copilot review instructions. Maintainers may still need to merge urgent repository maintenance changes when automation is blocked or delayed.

## Decision

Repository administrators may bypass branch protection for urgent maintenance. Normal contributor changes should still use pull requests, review, and required checks.

## Consequences

Maintainers retain an emergency path for repository health and security fixes. Admin bypass should be used deliberately, and follow-up validation should be run locally or in CI when practical.
