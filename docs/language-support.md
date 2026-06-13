# Language Support

Repository Trust Doctor is strongest when a repository exposes dependency manifests, CI/CD configuration, container files, and project metadata that can be reviewed statically.

## Stronger Ecosystem Support

| Ecosystem | Current coverage |
| --- | --- |
| JavaScript / TypeScript / Node.js | `package.json`, npm lockfiles, direct dependencies, version pinning, install-time scripts, direct Git/URL dependencies, npm registry metadata, OSV advisories |
| .NET / C# | `.csproj`, `Directory.Packages.props`, NuGet lockfiles, direct package references, MSBuild property-based package versions, NuGet sources, NuGet metadata, OSV advisories |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, common Python lockfiles, pinned requirement checks, documentation/test manifest suppression, PyPI metadata, OSV advisories |
| Java / Spring Boot | Maven `pom.xml`, Gradle `build.gradle` and `build.gradle.kts`, Gradle version catalogs (`libs.versions.toml`), Maven Central metadata, OSV advisories, BOM/dependency-management version signals, Gradle wrapper checks, dynamic/SNAPSHOT version checks, Spring Boot Actuator exposure checks |
| Go | `go.mod`, `go.sum` detection, replace directives, pseudo-version detection, prerelease/build metadata handling, version pinning |
| Rust / Cargo | `Cargo.toml` (direct sections, target-specific sections, dependency subtables), same-directory and workspace-root `Cargo.lock` detection, Git source detection, repository-external path source detection, version pinning, prerelease checks |
| PHP / Composer | `composer.json` (require/require-dev), `composer.lock` detection, version constraint analysis |
| Ruby / Bundler | `Gemfile`, `.gemspec`, `Gemfile.lock` detection, lockfile-aware version constraint analysis, Git/path source detection |
| Dart / Flutter | `pubspec.yaml` (dependencies/dev_dependencies with nested `sdk`, `path`, and `git` metadata handling), `pubspec.lock` detection, version constraint analysis |
| Elixir / Hex | `mix.exs`, `mix.lock` detection, version constraint analysis, non-Hex source detection |
| Swift / SPM | `Package.swift`, `Package.resolved` detection, branch-based dependency detection |
| C / C++ | `conanfile.txt`, `conanfile.py`, `vcpkg.json`, `CMakeLists.txt` (find_package/FetchContent) detection |

## Candidate Ecosystems For v2

The dependency inventory architecture now uses per-ecosystem collectors. Future support can therefore grow by adding small collectors, registry clients, advisory mapping, and focused tests.

| Ecosystem | Candidate files | Useful trust signals |
| --- | --- | --- |
| Go | `go.mod`, `go.sum` | module pinning, missing `go.sum`, replace directives, pseudo-versions, OSV Go advisories |
| Rust | `Cargo.toml`, `Cargo.lock` | workspace lockfile coverage, external path/git dependencies, yanked crates, crates.io metadata, RustSec or OSV advisories |
| PHP | `composer.json`, `composer.lock` | lockfile coverage, Packagist metadata, abandoned packages, platform constraints |
| Ruby | `Gemfile`, `Gemfile.lock`, `.gemspec` | lockfile coverage, Git/path gems, RubyGems metadata, yanked gems |
| Swift | `Package.swift`, `Package.resolved` | resolved package evidence, branch/revision dependencies, package URL provenance |
| Dart / Flutter | `pubspec.yaml`, `pubspec.lock` | lockfile coverage, hosted/path/git packages, pub.dev metadata |
| Elixir / Erlang | `mix.exs`, `mix.lock`, `rebar.config` | lockfile coverage, Hex metadata, Git/path dependencies |
| C / C++ | `conanfile.*`, `vcpkg.json`, `CMakeLists.txt` | package manager detection, registry source review, vendored dependency warnings |
| Android / Kotlin | Gradle version catalogs, `libs.versions.toml` | version catalog parsing, Android plugin versions, dynamic dependency ranges |

## Language-Independent Coverage

These checks apply across repositories regardless of programming language:

- repository health and adoption metadata,
- GitHub Actions workflow security,
- Dockerfile and container hygiene,
- secret quick scanning,
- release evidence and checksum/provenance signals,
- dependency freshness, license, origin, and vulnerability review when package inventory exists,
- codebase-level signals such as public API and critical-code heuristics.

## Static-Only Boundary

Scans do not execute repository code, run package managers, build containers, run tests, or invoke Maven/Gradle/npm/pip. Java and Spring Boot support is based on static files and safe metadata/advisory lookups.
