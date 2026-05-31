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
