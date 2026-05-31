# ADR 0001: Static Analysis By Default

Status: Accepted

## Context

Repository Trust Doctor analyzes repositories that must be treated as untrusted input. Build scripts, package lifecycle scripts, test commands, and local tooling may execute arbitrary code if run automatically.

## Decision

Scans are static-only by default. Analyzer modules may read repository files, parse metadata, and query safe external metadata sources, but they must not execute repository code unless a future explicit sandboxed mode is designed and enabled by the user.

## Consequences

Default scans are safer for local and hosted use, but some signals that require execution will be missing or lower confidence. Analyzers should report uncertainty instead of attempting unsafe execution.
