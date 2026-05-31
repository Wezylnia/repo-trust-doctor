# Copilot Review Instructions

When reviewing this repository, prioritize:

- untrusted repository input handling,
- places where repository code could accidentally be executed,
- file system traversal, large file reads, and temporary workspace cleanup,
- secret redaction and evidence handling,
- analyzer isolation and failure behavior,
- GitHub Actions permission scope and action pinning,
- documentation drift for security-sensitive behavior.

Do not suggest executing scanned repository code by default. Hosted or API-based file intake must include explicit upload policy, size limits, timeouts, workspace isolation, and abuse controls.
