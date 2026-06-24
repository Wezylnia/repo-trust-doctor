# API And Worker

Repository Trust Doctor `v1.0.5` includes local API and worker hosts built on the same application scan lifecycle as the CLI.

The hosts are intentionally small. Analyzer composition lives in `RepoTrustDoctor.Infrastructure.Scanning`, scan lifecycle behavior lives in `RepoTrustDoctor.Application`, and the API only exposes scan operations.

## Run The API

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Api
```

Health:

```text
GET /health
```

Start a scan:

```text
POST /api/scans
Content-Type: application/json

{
  "target": "https://github.com/owner/repo",
  "depth": "standard",
  "trustProfile": "production"
}
```

The response is `202 Accepted` with a scan ID and status URL:

```json
{
  "scanId": "00000000-0000-0000-0000-000000000000",
  "status": "Queued",
  "statusUrl": "/api/scans/00000000-0000-0000-0000-000000000000"
}
```

The API accepts absolute `https://github.com/owner/repo` targets and rejects local paths, non-GitHub hosts, credentialed URLs, query strings, and fragments. Local path scans remain a CLI-only workflow for trusted local development.

API lifecycle and domain enum values are serialized as strings, for example `Completed`, `Fast`, and `ProductionDependency`. Active trust profile values are `Personal`, `ProductionDependency`, and `SecuritySensitiveDependency`; legacy CI/CD and container profile inputs are normalized to production.

## API Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Returns API health and product version |
| `POST` | `/api/scans` | Validates and queues a scan |
| `GET` | `/api/scans` | Lists known scan statuses |
| `GET` | `/api/scans/{scanId}` | Returns scan status, module count, finding count, score, and decision |
| `GET` | `/api/scans/{scanId}/progress` | Returns lifecycle and module progress |
| `GET` | `/api/scans/{scanId}/modules` | Returns completed scan modules |
| `GET` | `/api/scans/{scanId}/findings` | Returns completed scan findings |
| `GET` | `/api/scans/{scanId}/report?format=json` | Returns JSON, Markdown, or SARIF report output |
| `POST` | `/api/scans/{scanId}/cancel` | Requests scan cancellation |

Report formats are `json`, `markdown`, `md`, and `sarif`.

## Run The Worker

```powershell
dotnet run --project src/Apps/RepoTrustDoctor.Worker
```

The worker host uses the same queue, scan processor, cancellation, and runner abstractions as the API host. The `v1.0.0` worker is a foundation for future persistent queues and scheduled scans.

## Local Intelligence Refresh

API and worker hosts read `RepoTrustDoctor:LocalIntelligence` configuration. Both use the SQLite registry cache and local OSV index during scans. The 24-hour hosted refresh loop is present but `BackgroundRefreshEnabled` is `false` in the checked-in configuration, so local development does not download OSV archives automatically.

Production should enable the updater in only one host that owns the persistent database volume. Full OSV ecosystem archives are refreshed weekly by default; intervening cycles use the modified-advisory index. Registry refreshes are limited to expired packages already observed by scans. See [Local Dependency Intelligence](local-intelligence.md) for configuration and operational guidance.

## Current Storage Model

`v1.0.0` uses in-memory scan state and an in-memory queue:

- state is process-local,
- scan records are lost when the host stops,
- API and worker processes do not share a queue unless a future persistence adapter is added,
- reports are generated from completed in-memory scan results.

This keeps the release static-only and easy to run locally while preserving clear seams for durable storage later.

## Safety

API and worker scans use the same safety posture as CLI scans:

- repository code is not executed by default,
- public HTTP(S) Git URLs are shallow-cloned with the existing Git workspace safeguards,
- credentialed repository URLs are rejected,
- dependency metadata and advisory downloads remain behind allowlisted safe HTTP clients, while repeated lookups use the local SQLite intelligence database,
- analyzer failures are isolated and surfaced as scan/module failures instead of crashing the host,
- unexpected scan and analyzer exceptions use generic user-facing status messages so raw exception text is not exposed through API status, progress, module, or report responses.
