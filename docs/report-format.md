# Report Format

Reports are evidence-based summaries of a scan.

The initial report model includes:

- repository path or URL,
- scan mode,
- trust profile,
- started and completed timestamps,
- module statuses,
- findings,
- category scores,
- overall score,
- final decision,
- recommended actions.

Each finding includes:

- rule ID,
- title,
- category,
- severity,
- confidence,
- message,
- evidence,
- recommendation,
- blocking flag.

Reports should be readable in Markdown and deterministic in JSON.
