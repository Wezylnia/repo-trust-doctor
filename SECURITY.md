# Security Policy

Repository Trust Doctor analyzes untrusted repositories, so security reports are welcome.

## Reporting a Vulnerability

Please do not open a public issue for a confirmed vulnerability. Contact the maintainer privately and include:

- affected version or commit,
- reproduction steps,
- expected impact,
- any relevant logs or sample files with secrets removed.

## Scanner Safety Baseline

The scanner must not execute repository code by default. Static file parsing and safe metadata lookups are the expected baseline for hosted or default scans.

Possible secret findings should be redacted in reports.

## Input Handling Baseline

Repository Trust Doctor treats every scanned repository as untrusted input.

Current safeguards:

- The CLI accepts local repository directories and absolute HTTP(S) Git repository URLs.
- Repository URLs must not contain usernames, passwords, tokens, or URL fragments.
- Public URL scans use shallow clone and do not recurse into submodules.
- Git clone disables `file` and `ext` protocols for the clone process.
- Static analyzers skip generated/local folders such as `.git`, `bin`, `obj`, `node_modules`, `.repo-trust`, and ignored private source notes.
- Static analyzers apply a maximum readable text file size before reading file contents.
- Report output refuses to overwrite an existing file unless `--force` is explicitly provided.

Current non-goals:

- The project does not accept arbitrary uploaded files.
- The project does not execute package installation, build, test, Docker build, or repository scripts by default.
- The current CLI does not provide hosted scanning or multi-user file intake.

Future hosted or API-based scanning must add explicit upload policy, repository size limits, per-scan timeouts, workspace isolation, and abuse controls before accepting user-provided archives or files.
