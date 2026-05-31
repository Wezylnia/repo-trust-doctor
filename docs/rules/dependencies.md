# Dependency Rules

## TRUST-DEP001: npm Manifest Exists but Lockfile Is Missing

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects repositories with `package.json` but no matching lockfile (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`).

Why it matters: without a lockfile, dependency resolution is non-deterministic and builds are not reproducible, exposing the repository to dependency drift and security risk.

Recommendation: install dependencies locally and commit the generated `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` to the repository.

## TRUST-DEP002: NuGet Project Does Not Use Lockfile

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects .NET repositories containing `.csproj` projects that do not use NuGet lock files (`packages.lock.json`).

Why it matters: NuGet default behavior is to resolve package dependencies dynamically, which can lead to non-reproducible builds if packages are updated or deleted from package feeds.

Recommendation: enable NuGet Central Package Management or local project lock files, restore packages to generate `packages.lock.json`, and commit it to the repository.

## TRUST-DEP003: Python Dependency Manifest Does Not Have a Recognized Lockfile

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects Python repositories containing dependency manifests (`requirements.txt`, `pyproject.toml`, or `Pipfile`) without matching lockfiles (`poetry.lock`, `Pipfile.lock`, or `uv.lock`).

Why it matters: raw manifests without a lockfile do not guarantee that the exact same package versions will be installed on different systems or runs.

Recommendation: use a package manager like Poetry, uv, or Pipenv, lock the dependencies, and commit the generated lockfile.
