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

## TRUST-DEP004: NuGet Dependency Uses a Floating or Unpinned Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects direct NuGet dependencies whose version is missing, floating, wildcard-based, or range-based.

Why it matters: floating and range-based dependencies can change without a source change, making builds less reproducible and dependency reviews harder.

Recommendation: pin direct NuGet dependency versions or resolve them through Central Package Management.

## TRUST-DEP005: NuGet Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects direct NuGet dependencies with prerelease version labels such as beta, alpha, rc, or preview.

Why it matters: prerelease dependencies may change behavior more frequently and may not have the same compatibility expectations as stable packages.

Recommendation: review whether the prerelease dependency is intentional before production use.

## TRUST-DEP006: npm Dependency Uses a Range or Unpinned Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects npm dependencies in `package.json` that use ranges, tags, workspace references, file references, or other non-exact versions.

Why it matters: non-exact dependency specifications can produce different installs over time. Lockfiles reduce this risk, but exact direct dependency declarations are easier to review.

Recommendation: use exact dependency versions together with a committed lockfile for reproducible installs.

## TRUST-DEP007: npm Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects npm dependencies with prerelease version labels.

Why it matters: prerelease packages may be appropriate for testing, but they deserve manual review before production dependency use.

Recommendation: review prerelease dependencies and prefer stable versions where possible.

## TRUST-DEP008: npm Install-Time Script Requires Manual Review

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects `preinstall`, `install`, or `postinstall` scripts in `package.json`.

Why it matters: install-time scripts run during package installation. A compromised or surprising install script can execute code on a developer or CI machine.

Recommendation: review install-time scripts and avoid downloading or executing untrusted remote code.

## TRUST-DEP009: Python Requirement Is Unpinned

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Python dependencies that are missing an exact pinned version.

Why it matters: unpinned Python requirements can resolve to different packages over time and make repository review less repeatable.

Recommendation: pin Python requirements or use a lockfile-based package manager.

## TRUST-DEP010: Python Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Python dependencies with prerelease version labels.

Why it matters: prerelease dependencies may be unstable or intentionally experimental.

Recommendation: review whether the prerelease dependency is intentional before production use.

## TRUST-DEP011: npm Dependency Uses a Direct Remote Source

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects npm dependencies in `package.json` that point directly to Git, GitHub shorthand, HTTP, or HTTPS sources instead of normal registry versions.

Why it matters: direct remote dependency sources can bypass normal registry provenance and review workflows. They may also change behavior if a branch or moving ref is used.

Recommendation: review direct remote dependency sources and prefer registry packages with pinned versions when possible.

## TRUST-DEP012: npm Dependency Uses a Local File Source

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects npm dependencies that use local `file:`, `link:`, `workspace:`, or `portal:` references.

Why it matters: local dependency sources depend on repository layout and package manager behavior. They can be legitimate in monorepos, but they deserve review because they bypass registry provenance.

Recommendation: review local dependency sources and ensure they are intentional, documented, and covered by the repository's dependency review process.

## TRUST-DEP013: NuGet Package Source Uses Insecure Transport

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects NuGet package sources configured with HTTP instead of HTTPS.

Why it matters: plaintext package sources can expose metadata and credentials, and they weaken package integrity assumptions.

Recommendation: use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport.

## TRUST-DEP014: NuGet Package Source Uses a Local Path

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects NuGet package sources that point to local filesystem paths.

Why it matters: local package sources can be legitimate for development, but they change package-origin assumptions and may hide dependency confusion or provenance gaps.

Recommendation: review local package sources and document whether they are development-only or part of the supported build process.
