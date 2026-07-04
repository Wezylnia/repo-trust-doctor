# Local Dependency Intelligence

Repository Trust Doctor stores dependency intelligence in a shared SQLite database. The local layer reduces repeated registry requests, allows OSV checks to run without one API request per package, and preserves usable stale metadata during temporary registry failures.

## Storage

The default database path is:

```text
%LOCALAPPDATA%\RepoTrustDoctor\intelligence.db
```

`LocalIntelligenceOptions.DatabasePath` can point to a persistent application volume in production. SQLite uses WAL mode, foreign keys, a 30-second busy timeout, and a versioned schema.

An older application build refuses to modify a database whose schema version
is newer than it supports. Registry metadata then falls back to direct registry
lookups, and vulnerability analysis uses online OSV fallback when configured;
the newer schema marker and database contents are left unchanged.

The database contains:

- version-specific package metadata cache entries,
- raw OSV advisory documents,
- normalized OSV ecosystem/package lookup mappings,
- feed readiness and refresh timestamps.

## Registry Metadata

NuGet, npm, PyPI, and Maven Central metadata is cached on demand. A package/version lookup first checks SQLite:

- a fresh entry is returned without network access,
- a missing or expired entry is fetched from the allowlisted registry and written to SQLite,
- an expired positive entry is returned as stale data if the registry refresh fails,
- concurrent requests for the same package/version share one network lookup within a scan.

Only a confirmed package-not-found response is stored as a negative cache
entry. Timeouts, rate limits, registry server errors, transport failures,
rejected requests, blocked requests, oversized responses, and invalid payloads
are not negative-cached. Analyzer metrics and warnings distinguish rate limits,
server errors, rejected requests, invalid responses, and local policy blocks. A
stale negative entry is never used to hide a failed refresh.

The background refresh only revisits expired packages already present in the cache. It does not mirror complete public registries; complete npm, NuGet, PyPI, and Maven indexes would be much larger and more operationally complex than the OSV dataset.

Package metadata includes `lookup.source` with `sqlite`, `network`, or `sqlite-stale`. Analyzer metrics expose cache-hit and network lookup counts.

NuGet registration metadata can arrive in pages that are not safe to interpret
with lexical string ordering. The parser selects the latest NuGet version using
numeric release components and prerelease precedence before freshness rules use
that value.

npm and PyPI metadata distinguish the requested dependency version from the
registry's latest release. Freshness comparison uses the latest version, while
license, deprecation, yanked status, repository URL, and publication time come
from the requested version. PyPI loads the exact-version endpoint when the
requested version differs from latest. If exact-version metadata is unavailable,
the scanner leaves those fields unknown instead of attributing latest-release
metadata to the installed dependency.

Real scan validation across NuGet, npm, Maven, and PyPI confirmed that a second
scan against the same database performed zero registry requests. The measured
metadata analyzer times were:

| Ecosystem corpus | Cold | Warm | Warm cache hits |
| --- | ---: | ---: | ---: |
| NuGet (`nuget-license`) | 1,598 ms | 12 ms | 11 |
| npm (`react`) | 2,786 ms | 10 ms | 9 |
| Maven (`spring-framework`) | 1,675 ms | 6 ms | 7 |
| PyPI (`home-assistant-core`) | 6,707 ms | 13 ms | 48 |

The database also stores confirmed not-found lookups, so the row count can be
larger than the number of metadata objects returned to analyzers.

## Local OSV Index

The updater downloads official ecosystem archives from:

```text
https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
```

Each archive is validated for entry count, single-entry size, and expanded size before its records replace the previous ecosystem mappings in one transaction. A malformed or empty archive does not erase the existing usable index.

After a full import, daily refreshes read the official `modified_id.csv` index and fetch only advisories modified since the last successful update. A full ecosystem archive is imported again every seven days by default. Failure in one ecosystem does not prevent the remaining ecosystems from refreshing.

Incremental imports first clear the modified advisory's previous package mappings for that ecosystem. If the updated advisory no longer affects the ecosystem, stale package matches are removed instead of lingering until the next full archive import.

Local matching supports exact affected-version lists and OSV `SEMVER` ranges.
OSV range boundaries with one, two, or three numeric components are normalized
to semantic versions, so feed values such as `10.0` are evaluated as
`10.0.0`. Ecosystem-specific or Git ranges that cannot be evaluated
conservatively are sent to the online OSV fallback instead of being treated as
clean. Reports expose local and online package counts:

- `dependency.vulnerability.lookup.local.count`
- `dependency.vulnerability.lookup.online.count`
- `dependency.vulnerability.lookup.completed.count`
- `dependency.vulnerability.lookup.incomplete.count`
- `dependency.vulnerability.batch.attempted.count`
- `dependency.vulnerability.batch.returned.count`

Soft-budget metrics distinguish work that was started from work that returned a
result. Metadata uses `dependency.metadata.lookup.attempted.count` and
`dependency.metadata.lookup.returned.count`; vulnerability batches expose the
same distinction so canceled in-flight requests do not disappear from reports.

Before an ecosystem has a ready local index, vulnerability checks use `api.osv.dev` when online fallback is enabled. If fallback is disabled, the analyzer records incomplete coverage rather than reporting an unverified clean result.

Local lookup failures degrade to the online client when fallback is enabled,
and a corrupt or temporarily unavailable SQLite cache does not discard
successful registry metadata. Confirmed local advisories are preserved even
when another candidate advisory for the same package has range semantics that
require online evaluation. Online fallback results are merged with the certain
local advisories instead of replacing them.

Advisory severity uses explicit OSV severity fields when available. Numeric
CVSS scores are mapped to the usual critical/high/medium/low bands, and CVSS
v3 vector strings are scored locally before classification.

Completion is counted per package rather than per batch. A mixed batch can
therefore report locally completed packages and preserved findings while also
reporting incomplete packages whose ecosystem data is not ready or whose range
semantics require online fallback.

## Background Refresh

The API and worker can host a refresh service, but it is disabled by default:

```json
{
  "RepoTrustDoctor": {
    "LocalIntelligence": {
      "BackgroundRefreshEnabled": false,
      "RefreshInterval": "1.00:00:00",
      "FullOsvRefreshInterval": "7.00:00:00"
    }
  }
}
```

Enable it only in the production host that owns the persistent SQLite volume:

```powershell
$env:RepoTrustDoctor__LocalIntelligence__BackgroundRefreshEnabled = "true"
$env:RepoTrustDoctor__LocalIntelligence__DatabasePath = "D:\repo-trust-data\intelligence.db"
```

Run one active updater against a shared database. Other scanner instances can use the same durable database with background refresh disabled.

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `DatabasePath` | Local application data | SQLite database location |
| `RegistryCacheEnabled` | `true` | Enables package metadata cache reads and writes |
| `RegistryCacheTtl` | 24 hours | Freshness window for registry metadata |
| `RegistryRefreshBatchSize` | `10000` | Maximum expired cache entries refreshed per cycle |
| `RegistryRefreshConcurrency` | `8` | Maximum concurrent registry refresh requests |
| `LocalOsvEnabled` | `true` | Enables SQLite OSV queries |
| `OsvOnlineFallbackEnabled` | `true` | Uses OSV API for missing or inconclusive local coverage |
| `BackgroundRefreshEnabled` | `false` | Starts the hosted refresh loop |
| `RefreshInterval` | 24 hours | Hosted refresh interval |
| `FullOsvRefreshInterval` | 7 days | Maximum age before a full ecosystem reimport |

The default OSV ecosystem list covers npm, NuGet, PyPI, Maven, Go, crates.io, Packagist, RubyGems, Pub, Hex, and SwiftURL.

## Troubleshooting

To confirm the SQLite cache is being used, inspect dependency metadata and vulnerability metrics in JSON or Markdown reports. Useful fields include:

- `dependency.metadata.cache.hit.count`
- `dependency.metadata.lookup.network.count`
- `dependency.metadata.lookup.stale_used.count`
- `dependency.metadata.lookup.attempted.count`
- `dependency.metadata.lookup.returned.count`
- `dependency.vulnerability.lookup.local.count`
- `dependency.vulnerability.lookup.online.count`
- `dependency.vulnerability.lookup.incomplete.count`

Package metadata records expose `lookup.source`:

- `sqlite` means a fresh local cache entry was used.
- `network` means the scanner queried an allowlisted registry and may have updated SQLite.
- `sqlite-stale` means an expired positive cache entry was used because refresh failed; this is a resilience fallback, not a confirmed fresh registry result.

Slow-network scans usually show higher network lookup counts, timeout or rate-limit warnings, and lower returned counts than attempted counts. Offline scans should still use fresh SQLite entries and usable stale positive entries. If local OSV data is not ready, vulnerability checks use online OSV fallback when enabled; with fallback disabled, reports mark coverage incomplete instead of reporting an unverified clean result.

For production hosts, enable background refresh only on the instance that owns the persistent database volume. Other API or worker instances should keep `BackgroundRefreshEnabled` disabled and reuse the same durable `DatabasePath`.

Safe cleanup is limited to stopping scanner hosts and deleting the configured SQLite database when you intentionally want to rebuild local intelligence from scratch. Do not delete a shared production database while a refresh service or scan is active.
