# Dependency Rules

## TRUST-DEP001: npm Manifest Exists but Lockfile Is Missing

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects `package.json` manifests without a covering lockfile (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`) in the manifest directory or an ancestor workspace directory.

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

Detects direct NuGet dependencies whose version is missing, floating, wildcard-based, or range-based. MSBuild property values from common `.props` and `.targets` files are resolved before this rule is evaluated. Dynamic MSBuild expressions such as `$(...)`, `@(...)`, and `%(...)` are inventoried when possible but are not reported as floating versions unless they can be resolved to an actual floating value.

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

Detects npm dependencies in `package.json` that use ranges, tags, or other non-exact registry versions when no covering lockfile is present.

Why it matters: non-exact dependency specifications can produce different installs over time when there is no committed lockfile covering the manifest.

Recommendation: use exact dependency versions or commit a package-manager lockfile that covers the manifest.

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

Detects Python dependencies that are missing an exact pinned version. For `pyproject.toml`, only `[project].dependencies` and Poetry dependency sections are interpreted as dependencies; classifiers and other metadata arrays are ignored. Python manifests under common documentation, sample, fixture, and test paths are still inventoried but do not emit version-pinning findings.

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

Detects npm dependencies that use local `file:`, `link:`, or `portal:` references. Workspace protocol dependencies are recorded as workspace-internal package references instead of local file-source risks. Local-source dependencies in common test, fixture, example, or playground manifests are recorded in inventory but do not emit this finding.

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

## TRUST-DEP015: Dependency Appears Outdated

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects direct production dependencies where package metadata reports a newer major version than the requested version. Development dependencies and packages declared only in common test, fixture, example, or playground manifests are skipped for metadata freshness findings.

Why it matters: major-version drift can indicate missed maintenance, unfixed defects, or delayed security updates. It is not automatically unsafe, but it is useful review evidence.

Recommendation: review the dependency changelog and plan an update if compatible.

## TRUST-DEP016: Dependency Package Is Deprecated or Yanked

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects package metadata that clearly marks a production dependency as deprecated or yanked. Development dependencies and packages declared only in common test, fixture, example, or playground manifests are skipped for metadata deprecation findings.

Why it matters: deprecated or yanked packages may no longer receive fixes or may have been withdrawn because of correctness, security, or maintenance concerns.

Recommendation: replace deprecated packages or upgrade to a maintained version.

## TRUST-DEP017: Java Dependency Manifest Does Not Have a Recognized Lockfile

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects Maven or Gradle repositories with `pom.xml`, `build.gradle`, or `build.gradle.kts` files but no recognized dependency lock evidence such as `gradle.lockfile`, `dependencies.lock`, or `maven-dependency-lock.json`.

Why it matters: Java dependency resolution can drift when transitive dependencies are updated or when dynamic declarations are used. Lock evidence makes dependency review and repeatable builds easier.

Recommendation: commit Gradle dependency locking output or equivalent dependency lock evidence for repeatable Java builds.

## TRUST-DEP018: Java Dependency Uses a Dynamic or Unpinned Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Maven or Gradle dependencies with missing versions, dynamic Gradle versions such as `+`, Maven version ranges, unresolved Maven properties, or legacy `LATEST` / `RELEASE` declarations. Dependencies whose versions are supplied by Maven parent/dependency-management sections, Spring/Gradle dependency-management plugins, BOM/platform declarations, or Gradle property-style declarations are recorded as managed versions instead of unpinned dependencies.

Why it matters: dynamic Java dependency declarations can resolve to different artifacts over time, making security review and build reproduction harder.

Recommendation: pin Java dependency versions or resolve them through a reviewed platform/BOM.

## TRUST-DEP019: Java Dependency Uses a Snapshot or Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Java dependencies using `SNAPSHOT`, milestone, beta, alpha, release-candidate, or preview-style versions.

Why it matters: prerelease and snapshot artifacts can change more frequently and may not carry the same production stability expectations as release artifacts.

Recommendation: review whether the Java prerelease dependency is intentional before production use.

## TRUST-DEP020: Gradle Project Does Not Include Wrapper Scripts

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects Gradle builds without both `gradlew` and `gradle/wrapper/gradle-wrapper.properties`.

Why it matters: without a wrapper, reviewers cannot easily see the expected Gradle distribution and builds may depend on whichever Gradle version exists on the host.

Recommendation: commit `gradlew`, `gradlew.bat`, and the wrapper properties file so reviewers can see the expected Gradle distribution.

## TRUST-DEP021: Spring Boot Actuator Exposes Broad Endpoint Access

- Category: Dependencies
- Default severity: High
- Default confidence: Medium

Detects Spring Boot configuration where `management.endpoints.web.exposure.include` appears to expose all web endpoints.

Why it matters: broad Actuator exposure can publish operational details or sensitive management endpoints if network controls and authentication are not strict.

Recommendation: restrict `management.endpoints.web.exposure.include` to the minimum required endpoints and protect management interfaces.

## TRUST-ORIGIN001: Package Repository URL Does Not Match Analyzed Repository

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects package registry metadata whose repository URL points to a different repository than the scanned target when both URLs can be compared safely.

Why it matters: repository metadata mismatches can make package provenance harder to verify.

Recommendation: verify that package metadata points to the expected source repository.

## TRUST-ORIGIN002: Package Has Official-Looking Name From Unverified Origin

- Category: Dependencies
- Default severity: Low
- Default confidence: Low

Detects package names that resemble official namespaces while package origin metadata is incomplete.

Why it matters: official-looking package names deserve manual review when provenance metadata is missing or weak.

Recommendation: manually verify the package publisher and repository before relying on it.

## TRUST-ORIGIN003: Package Origin Metadata Is Incomplete

- Category: Dependencies
- Default severity: Low
- Default confidence: Medium

Detects package metadata that does not include a repository URL.

Why it matters: missing source metadata makes it harder to trace package origin, review source history, or compare package and repository state.

Recommendation: prefer dependencies with traceable repository metadata.

## TRUST-ORIGIN004: Package Source Mapping Is Missing for Mixed NuGet Sources

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects NuGet configuration that mixes public and non-public package sources without visible package source mapping.

Why it matters: mixed feeds without source mapping can increase dependency confusion risk.

Recommendation: add NuGet package source mapping to reduce dependency confusion risk.

## TRUST-ORIGIN005: npm Scope Registry Configuration Appears Risky

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects internal-looking scoped npm dependencies without matching scoped registry configuration.

Why it matters: private scopes should normally map explicitly to private registries so package resolution does not accidentally fall back to a public registry.

Recommendation: add explicit scope registry mapping in `.npmrc` for private scopes.

## TRUST-ORIGIN006: Internal-Looking Package Is Resolved From a Public Registry

- Category: Dependencies
- Default severity: Medium
- Default confidence: Medium

Detects internal-looking package names that appear to use normal public registry resolution.

Why it matters: internal-looking names on public registries can be dependency-confusion review signals.

Recommendation: verify whether the package should come from a private registry.

## TRUST-DEP022: Go Module Does Not Have a go.sum File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Go repositories with `go.mod` but no `go.sum` alongside it.

Why it matters: without `go.sum`, Go module builds are not cryptographically verifiable and dependency versions can change without detection.

Recommendation: run `go mod tidy` and commit `go.sum` to the repository for reproducible builds.

## TRUST-DEP023: Go Module Uses Replace Directive

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects `replace` directives in `go.mod`.

Why it matters: replace directives override resolved module versions and can point to forks, local paths, or different module paths. They bypass normal module resolution and deserve manual review.

Recommendation: review replace directives because they override resolved module versions.

## TRUST-DEP024: Go Dependency Uses a Non-Exact Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Go module dependencies that do not use an exact semver-style version (e.g. `v1.2` instead of `v1.2.3`). Go prerelease, build-metadata, and pseudo-version values that include a full `vMAJOR.MINOR.PATCH` prefix are treated as exact module versions; pseudo-versions are reviewed separately by `TRUST-DEP025`.

Why it matters: non-exact Go dependency versions can resolve to different minor or patch versions over time, reducing build reproducibility.

Recommendation: use exact versions with a committed `go.sum` for reproducible Go builds.

## TRUST-DEP025: Go Dependency Uses a Pseudo-Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Go module dependencies that reference a pseudo-version (e.g. `v0.0.0-20240115120000-abcdef123456`).

Why it matters: pseudo-versions point to unreleased commits and can be less stable or intentionally temporary. They may also bypass normal release review processes.

Recommendation: prefer tagged releases over pseudo-versions and review pseudo-version origins.

## TRUST-DEP026: Cargo Project Does Not Have a Cargo.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Rust repositories with `Cargo.toml` but no `Cargo.lock` alongside it.

Why it matters: without `Cargo.lock`, dependency resolution is non-deterministic and builds are not reproducible, exposing the repository to dependency drift.

Recommendation: commit `Cargo.lock` to the repository for reproducible builds (recommended for binaries).

## TRUST-DEP027: Cargo Dependency Uses a Git Source

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Cargo dependencies that reference a Git repository instead of a crates.io version.

Why it matters: Git-sourced dependencies can change behavior when a branch or moving ref is used, and they bypass normal crates.io provenance and review workflows.

Recommendation: review Git-sourced dependencies and prefer crates.io packages with pinned versions when possible.

## TRUST-DEP028: Cargo Dependency Uses a Path Source

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Cargo dependencies that reference a local filesystem path instead of a registry version.

Why it matters: path-sourced dependencies depend on repository layout and may bypass registry provenance. They can be legitimate in workspaces but deserve review.

Recommendation: review path-sourced dependencies and document whether they are workspace-internal or development-only.

## TRUST-DEP029: Cargo Dependency Uses a Non-Exact Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Cargo dependencies that do not use an exact requirement (e.g. `"1"`, `"1.2"`, or `"1.2.3"` instead of `"=1.2.3"`). The collector reads normal dependency sections, target-specific dependency sections, and dependency subtables such as `[dependencies.serde]` without treating metadata keys like `features` as packages.

Why it matters: non-exact Cargo dependency versions can resolve to different minor or patch versions over time.

Recommendation: use exact `=x.y.z` requirements when strict direct dependency pinning is required, and commit `Cargo.lock` for reproducible Cargo builds.

## TRUST-DEP030: Cargo Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Cargo dependencies with prerelease version labels (e.g. `"1.0.0-alpha.1"`).

Why it matters: prerelease dependencies may be unstable or intentionally experimental.

Recommendation: review whether the prerelease dependency is intentional before production use.

## TRUST-DEP031: Composer Project Does Not Have a composer.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects PHP repositories with `composer.json` but no `composer.lock` alongside it.

Why it matters: without `composer.lock`, dependency resolution is non-deterministic and builds are not reproducible.

Recommendation: run `composer install` and commit `composer.lock` to the repository for reproducible builds.

## TRUST-DEP032: Composer Dependency Uses a Non-Exact Version Constraint

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Composer dependencies that use version constraints (`^`, `~`, `>`, `<`, `*`, `||`) instead of exact versions.

Why it matters: version constraints can resolve to different package versions over time, making builds less reproducible.

Recommendation: use exact version constraints or commit `composer.lock` for reproducible installs.

## TRUST-DEP033: Composer Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Composer dependencies with prerelease version labels (e.g. `"1.0.0-beta.1"`).

Why it matters: prerelease dependencies may be unstable or intentionally experimental.

Recommendation: review whether the prerelease dependency is intentional before production use.

## TRUST-DEP034: Ruby Gemfile Does Not Have a Gemfile.lock

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Ruby repositories with `Gemfile` but no sibling `Gemfile.lock`.

Why it matters: without `Gemfile.lock`, Bundler may resolve different gem versions over time.

Recommendation: run `bundle install` and commit `Gemfile.lock` for reproducible builds.

## TRUST-DEP035: Ruby Gem Uses a Non-Exact Version Constraint

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Ruby gems with missing or non-exact version constraints. `Gemfile` constraints are not reported when a sibling `Gemfile.lock` exists, because Bundler's lockfile provides the reproducible resolution. Gemspec constraints still emit this rule because they describe package compatibility rather than an application install lock.

Why it matters: missing or ranged gem constraints can resolve to different versions over time.

Recommendation: use exact gem versions with a committed `Gemfile.lock` for reproducible builds.

## TRUST-DEP036: Ruby Gem Uses a Git or Path Source

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Ruby gems sourced from Git repositories or local paths instead of RubyGems.

Why it matters: non-registry gem sources can bypass registry provenance and may change if a moving branch or local path is used.

Recommendation: review non-registry gem sources and prefer RubyGems packages with pinned versions when possible.

## TRUST-DEP037: Dart Project Does Not Have a pubspec.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Dart or Flutter application-like repositories with `pubspec.yaml` but no sibling `pubspec.lock`. Root target manifests and nested manifests with application signals such as platform folders, `web/`, or `lib/main.dart` are eligible. Library, tool, example, CI, and test package manifests are inventoried but do not emit this reproducibility warning.

Why it matters: without a lockfile, package resolution can drift between installs.

Recommendation: run `dart pub get` or `flutter pub get` and commit `pubspec.lock` where appropriate for applications.

## TRUST-DEP038: Dart Dependency Uses a Non-Exact Version Constraint

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Dart application dependencies with version ranges or constraints instead of exact versions when no sibling `pubspec.lock` exists. Nested Pub metadata such as `sdk: flutter`, `path: ../package`, and `git:` is associated with the parent dependency instead of being recorded as a package.

Why it matters: version constraints can resolve to different package versions over time.

Recommendation: use exact version constraints with a committed `pubspec.lock` for reproducible builds in application manifests.

## TRUST-DEP040: Elixir Project Does Not Have a mix.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Elixir repositories with `mix.exs` but no sibling `mix.lock`.

Why it matters: without `mix.lock`, dependency resolution can drift between installs.

Recommendation: run `mix deps.get` and commit `mix.lock`.

## TRUST-DEP041: Elixir Dependency Uses a Non-Exact Version Constraint

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Elixir dependencies with version constraints instead of exact versions.

Why it matters: version constraints can resolve to different package versions over time.

Recommendation: use exact version constraints with a committed `mix.lock` for reproducible builds.

## TRUST-DEP042: Elixir Dependency Uses a Non-Hex Source

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Elixir dependencies sourced from Git or local paths instead of Hex.

Why it matters: non-Hex sources can bypass registry provenance and may depend on moving refs or local repository layout.

Recommendation: review non-Hex dependency sources and prefer Hex packages with pinned versions when possible.

## TRUST-DEP043: Swift Package Does Not Have a Package.resolved File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Swift packages with `Package.swift` but no sibling `Package.resolved`.

Why it matters: without resolved package evidence, dependency versions may drift.

Recommendation: commit `Package.resolved` for reproducible Swift package resolution.

## TRUST-DEP044: Swift Package Uses a Branch-Based Dependency

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Swift package dependencies that reference a branch instead of a version.

Why it matters: branch-based dependencies can change without a manifest change.

Recommendation: prefer version-based dependencies with a committed `Package.resolved`.

## TRUST-DEP046: C/C++ Project Uses Conan Package Manager

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects `conanfile.txt` or `conanfile.py`.

Why it matters: C/C++ package manager evidence helps reviewers understand dependency sources that may otherwise be hidden in build scripts.

Recommendation: review Conan dependencies and commit lockfiles where the project uses them.

## TRUST-DEP047: C/C++ Project Uses vcpkg

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects `vcpkg.json`.

Why it matters: vcpkg manifests define native dependencies that should be reviewed alongside application code.

Recommendation: review vcpkg dependencies and version constraints.

## TRUST-DEP048: C/C++ Project Uses CMake External Dependencies

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects `find_package` or `FetchContent_Declare` in `CMakeLists.txt`.

Why it matters: CMake can pull in external dependencies through build configuration.

Recommendation: review CMake external dependencies and document expected package sources.

## TRUST-DEP049: Ruby Gem Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Ruby gems with prerelease version labels.

Why it matters: prerelease gems may be unstable or intentionally experimental.

Recommendation: review whether the prerelease gem is intentional before production use.

## TRUST-DEP050: Gradle Version Catalog Uses Dynamic Dependency Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects dynamic version declarations in Gradle `libs.versions.toml` `[versions]` and `[libraries]` sections.

Why it matters: dynamic versions (e.g., `3.+`, `latest.release`) make builds non-reproducible and can silently introduce changes.

Recommendation: pin dependency versions to specific releases.

## TRUST-DEP051: Gradle Version Catalog Uses Dynamic Plugin Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects dynamic version declarations in Gradle `libs.versions.toml` `[plugins]` section.

Why it matters: plugin version drift can silently change build behavior.

Recommendation: pin plugin versions to specific releases.
