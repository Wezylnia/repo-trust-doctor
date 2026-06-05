# Package Manifest Fixtures

Use this folder for small synthetic dependency manifest fixtures used by analyzer tests.

Fixture rules:

- keep files minimal and focused on one parser behavior,
- use fake package names or well-known public package names only when needed for readability,
- do not include real credentials, private registry tokens, customer data, or internal hostnames,
- do not run package managers to generate fixtures unless the resulting file is intentionally small and reviewed,
- prefer deterministic fixture content over network calls,
- keep lockfiles tiny unless a specific parser test needs more structure.

Ecosystem folders:

- `NuGet/`
- `Npm/`
- `Python/`
