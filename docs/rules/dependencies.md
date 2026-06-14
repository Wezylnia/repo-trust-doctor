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

Detects Python dependency manifests (`requirements.txt`, `pyproject.toml`, or `Pipfile`) without a compatible sibling lockfile (`poetry.lock`, `Pipfile.lock`, or `uv.lock`). Lockfile coverage is evaluated per manifest directory, so a lockfile for one service does not hide an unlocked independent service in a monorepo.

Why it matters: raw manifests without a lockfile do not guarantee that the exact same package versions will be installed on different systems or runs.

Recommendation: use a package manager like Poetry, uv, or Pipenv, lock the dependencies, and commit the generated lockfile.

## TRUST-DEP004: NuGet Dependency Uses a Floating or Unpinned Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects direct NuGet dependencies whose version is missing, floating, wildcard-based, or range-based. MSBuild property values from common `.props` and `.targets` files are resolved before this rule is evaluated. Dynamic MSBuild expressions such as `$(...)`, `@(...)`, and `%(...)` are inventoried when possible but are not reported as floating versions unless they can be resolved to an actual floating value.

Why it matters: floating and range-based dependencies can change without a source change, making builds less reproducible and dependency reviews harder.

Recommendation: pin direct NuGet dependency versions or resolve them through Central Package Management.

NuGet's single-version bracket syntax, such as `[3.1.3]`, is treated as an exact pin and normalized to `3.1.3` for registry and advisory lookup. Conditional references to the same package in one project retain all inventory variants but emit at most one hygiene finding. Test, fixture, example, and documentation projects remain in the dependency inventory while their lockfile and version-hygiene findings are suppressed.

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

Detects npm dependencies in `package.json` that use ranges, tags, or other non-exact registry versions when no covering lockfile is present. Exact direct versions are resolved from npm `package-lock.json`, pnpm importer data, and matching Yarn selectors for downstream metadata and vulnerability analysis. npm aliases are normalized to their real registry package while preserving the declared alias in metadata; workspace and other non-registry protocols are never sent to registry or advisory clients.

Why it matters: non-exact dependency specifications can produce different installs over time when there is no committed lockfile covering the manifest.

Recommendation: use exact dependency versions or commit a package-manager lockfile that covers the manifest.

## TRUST-DEP007: npm Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects npm dependencies with prerelease version labels. Prerelease packages in common tooling, generated, test, fixture, example, and documentation manifests are still recorded in the dependency inventory but do not emit this finding.

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

Detects Python dependencies that are missing an exact pinned version. Exact versions successfully resolved from `Pipfile.lock`, `poetry.lock`, and `uv.lock` replace requested ranges for metadata and vulnerability analysis; merely detecting a lockfile does not suppress the finding when that package cannot be resolved from it. For `pyproject.toml`, only `[project].dependencies` and Poetry dependency sections are interpreted as dependencies; classifiers and other metadata arrays are ignored. Requirement extras preserve the underlying package identity. Python manifests under common documentation, sample, fixture, and test paths are still inventoried but do not emit version-pinning findings.

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

Large monorepos often declare many internal `link:` dependencies in a single root manifest. When one manifest contains more than 10 local npm sources, the analyzer emits one summarized `TRUST-DEP012` finding with sample package names instead of one finding per internal package. The dependency inventory still records every package and source kind.

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

Detects direct production dependencies where package metadata reports a newer major version than the requested version. Development dependencies and packages declared only in common test, fixture, example, or playground manifests are skipped for metadata freshness findings. NuGet freshness uses semantic version ordering for registry versions instead of lexical string ordering.

Why it matters: major-version drift can indicate missed maintenance, unfixed defects, or delayed security updates. It is not automatically unsafe, but it is useful review evidence.

Recommendation: review the dependency changelog and plan an update if compatible.

## TRUST-DEP016: Dependency Package Is Deprecated or Yanked

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects package metadata that clearly marks the requested production dependency version as deprecated or yanked. Development dependencies and packages declared only in common test, fixture, example, or playground manifests are skipped for metadata deprecation findings. Registry metadata from a newer release is not attributed to the installed version when exact-version metadata is unavailable.

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

## TRUST-REG001: Package Registry Uses HTTP

- Category: Dependencies
- Default severity: High
- Default confidence: High

Detects package registry URLs that use plaintext `http://` in registry configuration files such as `.npmrc`, NuGet config, Gradle settings, and Maven settings. Localhost development registries are ignored.

Why it matters: plaintext package registry traffic can expose package metadata and credentials and weakens package integrity assumptions.

Recommendation: use HTTPS package sources for non-local registries. Report evidence redacts URL credentials and query strings.

## TRUST-REG003: Inline Package Registry Token

- Category: Dependencies
- Default severity: High
- Default confidence: Medium

Detects literal package registry credentials in registry configuration, including scoped `.npmrc` entries such as `//registry.example/:_authToken=...`, `_auth`, `_password`, `password`, and NuGet `ClearTextPassword` values. Environment variable references are not reported.

Why it matters: registry tokens committed to source can allow package publishing, private package reads, or dependency tampering depending on token scope.

Recommendation: move registry credentials to environment variables, CI secrets, or a local developer credential store. Findings identify the key name but do not include the credential value.

## TRUST-DEP022: Go Module Does Not Have a go.sum File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Go manifest hygiene findings (`TRUST-DEP022`, `TRUST-DEP023`, `TRUST-DEP024`, and `TRUST-DEP025`) are suppressed for low-signal fixture, testdata, example, documentation, and Go crypto test-vector paths. Those `go.mod` files are still recorded in the dependency inventory, but they are not treated as production dependency management decisions.

Detects Go repositories with `go.mod` but no `go.sum` alongside it.

Why it matters: without `go.sum`, Go module builds are not cryptographically verifiable and dependency versions can change without detection.

Recommendation: run `go mod tidy` and commit `go.sum` to the repository for reproducible builds.

## TRUST-DEP023: Go Module Uses Replace Directive

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects `replace` directives in `go.mod`, including single-line directives and multi-line `replace (...)` blocks. Multiple `replace` directives in the same manifest are aggregated into one finding with sample evidence so large Go workspaces do not flood reports with one finding per line. Local replacements that resolve inside the scanned repository are treated as monorepo wiring and are recorded in the inventory without emitting this finding.

Why it matters: replace directives override resolved module versions and can point to forks, local paths, or different module paths. They bypass normal module resolution and deserve manual review.

Recommendation: review replace directives because they override resolved module versions.

## TRUST-DEP024: Go Dependency Uses a Non-Exact Version

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Go module dependencies that do not use an exact semver-style version (e.g. `v1.2` instead of `v1.2.3`). Go prerelease, build-metadata, and pseudo-version values that include a full `vMAJOR.MINOR.PATCH` prefix are treated as exact module versions; pseudo-versions are reviewed separately by `TRUST-DEP025`.

Why it matters: non-exact Go dependency versions can resolve to different minor or patch versions over time, reducing build reproducibility.

Recommendation: use exact versions with a committed `go.sum` for reproducible Go builds.

## TRUST-DEP025: Direct Go Dependency Uses a Pseudo-Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects direct Go module dependencies that reference a pseudo-version (e.g. `v0.0.0-20240115120000-abcdef123456`). Multiple direct pseudo-version dependencies in the same manifest are aggregated into one finding with sample evidence. Indirect pseudo-version dependencies are still recorded in the dependency inventory, but they do not emit this finding because they are transitive resolution evidence rather than direct dependency choices. Direct pseudo-versions whose module path is replaced by a local path inside the scanned repository are also recorded without emitting this finding because the local replacement is the effective source.

Why it matters: direct pseudo-versions point to unreleased commits and can be less stable or intentionally temporary. They may also bypass normal release review processes.

Recommendation: prefer tagged releases over direct pseudo-version dependencies and review pseudo-version origins.

## TRUST-DEP026: Cargo Project Does Not Have a Cargo.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Rust repositories with `Cargo.toml` but no covering `Cargo.lock`. A lockfile in the same directory counts, and a lockfile at an ancestor Cargo workspace root also covers member manifests.

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

Detects Cargo dependencies that reference a filesystem path outside the scanned repository instead of a registry version. Repository-local path dependencies are recorded in the dependency inventory without emitting this finding because they are normal Cargo workspace/internal crate evidence.

Why it matters: path-sourced dependencies outside the repository depend on local filesystem state and may bypass registry provenance. Repository-internal path dependencies are common in Cargo workspaces and are treated as lower-risk inventory evidence.

Recommendation: review path-sourced dependencies that leave the repository and prefer workspace-local crates or registry packages when possible.

## TRUST-DEP029: Cargo Dependency Uses a Non-Exact Version Without Lockfile

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Cargo dependencies that do not use an exact requirement (e.g. `"1"`, `"1.2"`, or `"1.2.3"` instead of `"=1.2.3"`) when no covering `Cargo.lock` is present. The collector still records non-exact requirements in the dependency inventory when a same-directory or workspace-root lockfile exists, but it does not emit this finding because the lockfile provides the reproducibility signal for normal Cargo projects. The collector reads normal dependency sections, target-specific dependency sections, and dependency subtables such as `[dependencies.serde]` without treating metadata keys like `features` as packages.

When a covering lockfile contains exactly one registry version for a direct
crate, that version is used for advisory lookup. Renamed dependencies use the
underlying `package` name. If the same crate name has multiple locked versions,
the collector keeps the manifest requirement unresolved instead of choosing an
arbitrary version.

Why it matters: non-exact Cargo dependency versions can resolve to different minor or patch versions over time when a lockfile is not committed.

Recommendation: commit `Cargo.lock` for reproducible Cargo builds, or use exact `=x.y.z` requirements when strict direct dependency pinning is required.

## TRUST-DEP030: Cargo Dependency Uses a Prerelease Version

- Category: Dependencies
- Default severity: Low
- Default confidence: High

Detects Cargo dependencies with prerelease version labels (e.g. `"1.0.0-alpha.1"`).

Why it matters: prerelease dependencies may be unstable or intentionally experimental.

Recommendation: review whether the prerelease dependency is intentional before production use.

## TRUST-DEP031: Composer Application Does Not Have a composer.lock File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Composer application manifests with no sibling `composer.lock`.

Why it matters: applications should commit `composer.lock` so production installs are reproducible. Reusable Composer libraries commonly publish version constraints without a lockfile, so library package manifests are not reported by this rule.

Recommendation: run `composer install` and commit `composer.lock` for application repositories.

## TRUST-DEP032: Composer Application Has Unlocked Version Constraints

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Composer application manifests that use version constraints (`^`, `~`, `>`, `<`, `*`, `||`) while no sibling `composer.lock` is present. Findings are aggregated per manifest with sample packages instead of reporting every dependency individually.

When `composer.lock` is present, direct `require` and `require-dev` entries are
resolved from the matching `packages` and `packages-dev` records. The requested
constraint remains in package metadata while the exact locked version is used
for registry and advisory lookup.

Why it matters: version constraints are normal for reusable Composer libraries, but application installs without `composer.lock` can resolve to different package versions over time.

Recommendation: commit `composer.lock` for applications. Do not pin every dependency exactly in reusable libraries unless that is an intentional compatibility decision.

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

Registry gems in the `GEM` section of `Gemfile.lock` are resolved to exact
versions for advisory lookup. Entries from `GIT` and `PATH` sections are not
treated as RubyGems registry packages.

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

Hosted packages in `pubspec.lock` resolve direct manifest constraints to exact
versions. SDK, path, and Git dependencies remain source-qualified and are not
misrepresented as hosted Pub packages.

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

Detects Elixir dependencies that cannot be resolved to an exact version. When
`mix.lock` is present, direct Hex constraints are resolved from the lockfile
before this rule is evaluated. Test, fixture, example, and documentation
manifests do not produce this hygiene finding.

Why it matters: an absent or stale lock entry leaves the effective dependency
version unclear and prevents reliable version-specific advisory checks.

Recommendation: commit an up-to-date `mix.lock` that resolves the dependency
to an exact version.

## TRUST-DEP042: Elixir Dependency Uses a Non-Hex Source

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Elixir dependencies sourced from Git or from paths outside the scanned
repository. Repository-local path dependencies and low-signal example/test
manifests are retained in inventory without producing this finding.

Why it matters: remote Git and repository-external path sources can bypass Hex
provenance or depend on mutable and machine-local state.

Recommendation: review non-Hex dependency sources and prefer Hex packages with pinned versions when possible.

## TRUST-DEP043: Swift Executable Package Does Not Have a Package.resolved File

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects executable Swift package products without `Package.resolved` at the
package root or under `.swiftpm`. Library packages and non-production
benchmark, example, fixture, generated, and test manifests are not required to
commit resolution state.

Why it matters: executable applications are deployed artifacts; without
resolved package evidence, their installed dependency versions may drift.

Recommendation: commit `Package.resolved` for reproducible executable builds.

## TRUST-DEP044: Swift Package Uses a Branch-Based Dependency

- Category: Dependencies
- Default severity: Medium
- Default confidence: High

Detects Swift package dependencies that reference a branch instead of a version.

Version-based remote dependencies are resolved from current and legacy
`Package.resolved` formats when an exact pin is available. Local path and
branch dependencies remain unresolved by design.

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

Detects `find_package` or `FetchContent_Declare` in `CMakeLists.txt`. CMake
manifests are streamed up to 8 MiB so large generated project definitions do
not disappear behind the general 512 KiB text-file guard.

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
