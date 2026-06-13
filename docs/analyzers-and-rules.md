# Analyzers & Rules Reference

Complete catalog of all analyzers, rule IDs, and analysis types in Repository Trust Doctor v1.7.5.

## Architecture

Analyzers implement `IRepositoryAnalyzer` and produce `Finding` records with rule IDs, severity, confidence, evidence, and recommendations. Each analyzer runs in isolation; failures are contained.

### Analysis Categories

| Category | Enum Value | Description |
|----------|-----------|-------------|
| Repository Health | `RepositoryHealth` | Project metadata, documentation, governance |
| CI/CD | `CiCd` | Pipeline/workflow security and hygiene |
| Security | `Security` | Secrets, credentials, sensitive files |
| Containers | `Containers` | Docker, Compose, Kubernetes manifests |
| Dependencies | `Dependencies` | Package manifests, lockfiles, registry config |
| Releases | `Releases` | Artifacts, SBOM, provenance, changelogs |
| Licenses | `Licenses` | License detection and compliance |
| Codebase | `Codebase` | Deep code intelligence, public API, routes |
| Documentation | `Documentation` | Documentation quality signals |
| Infrastructure | `Infrastructure` | Terraform and IaC security |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| `Critical` | Blocking risk; immediate attention required |
| `High` | Significant risk; should be addressed |
| `Medium` | Moderate risk; review recommended |
| `Low` | Minor concern; consider addressing |
| `Info` | Informational only; positive signal, not a risk |

### Confidence Levels

| Confidence | Meaning |
|------------|---------|
| `High` | Directly observable from static evidence |
| `Medium` | Heuristic or pattern-based detection |
| `Low` | Speculative; manual review recommended |

---

## Analyzers

### Repository Health

**Analyzer:** `RepositoryHealthAnalyzer` (`repository-health`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-REPO001 | README file is missing | Medium | High |
| TRUST-REPO002 | LICENSE file is missing | High | High |
| TRUST-REPO003 | SECURITY.md is missing | Medium | High |
| TRUST-REPO004 | Contributing guide is missing | Low | High |
| TRUST-REPO005 | CODE_OF_CONDUCT.md is missing | Info | High |
| TRUST-REPO006 | CODEOWNERS is missing | Info | High |
| TRUST-REPO007 | Issue template is missing | Info | High |
| TRUST-REPO008 | Pull request template is missing | Info | High |
| TRUST-REPO009 | CHANGELOG is missing | Info | High |
| TRUST-REPO010 | README lacks installation guidance | Low | Medium |
| TRUST-REPO011 | README lacks usage guidance | Low | Medium |
| TRUST-REPO012 | README lacks quick start guidance | Low | Medium |
| TRUST-REPO013 | Documentation folder is missing | Info | High |
| TRUST-REPO014 | README contains broken-looking local link | Low | Medium |

### Workspace Detection

**Analyzer:** `WorkspaceAnalyzer` (`workspace`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-WS001 | npm workspace detected | Info | High |
| TRUST-WS002 | Cargo workspace detected | Info | High |
| TRUST-WS003 | Go workspace detected | Info | High |

---

## CI/CD Analyzers

### GitHub Actions

**Analyzer:** `GitHubActionsBasicAnalyzer` (`github-actions-basic`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-GHA001 | Workflow permissions are not declared | Medium | High |
| TRUST-GHA002 | Workflow uses `permissions: write-all` | High | High |
| TRUST-GHA003 | Workflow uses `pull_request_target` | High | High |
| TRUST-GHA004 | Workflow pipes downloaded scripts into a shell | High | High |
| TRUST-GHA005 | External action is not pinned by SHA | Medium | High |
| TRUST-GHA006 | Workflow uses self-hosted runner | Medium | High |
| TRUST-GHA007 | Checkout may persist credentials | Low | Medium |
| TRUST-GHA008 | Workflow interpolates GitHub event data in shell | High | Medium |
| TRUST-GHA009 | Release workflow may publish without test dependency | High | Medium |
| TRUST-GHA010 | Workflow uploads overly broad artifact path | Medium | Medium |
| TRUST-GHA011 | Workflow does not restrict GITHUB_TOKEN scope | Medium | High |
| TRUST-GHA012 | Workflow deploys to an unprotected environment | Medium | Medium |
| TRUST-GHA013 | Workflow may contain hardcoded secret in step env | High | Medium |
| TRUST-GHA014 | Workflow may interpolate matrix values in shell | High | Medium |
| TRUST-GHA015 | `pull_request_target` workflow exposes secrets | High | Medium |
| TRUST-GHA016 | Workflow-level write permissions are overly broad | Medium | Medium |
| TRUST-GHA017 | Workflow uses overly broad cache path | Low | Medium |
| TRUST-GHA018 | Job container or service image uses `:latest` | Medium | High |

### GitLab CI

**Analyzer:** `GitLabCiAnalyzer` (`gitlab-ci`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-GLCI001 | GitLab CI uses remote includes | Medium | High |
| TRUST-GLCI002 | GitLab CI interpolates CI variables in shell | High | Medium |
| TRUST-GLCI003 | GitLab CI uses `:latest` image tag | Medium | High |
| TRUST-GLCI004 | GitLab CI uses deprecated `only`/`except` | Low | High |
| TRUST-GLCI005 | GitLab CI uses privileged Docker-in-Docker | High | Medium |
| TRUST-GLCI006 | GitLab CI cache uses broad repository path | Medium | Medium |

### Azure Pipelines

**Analyzer:** `AzurePipelinesAnalyzer` (`azure-pipelines`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-AZP001 | Script uses untrusted PR variable expansion | High | Medium |
| TRUST-AZP002 | Checkout persists credentials | Medium | High |
| TRUST-AZP003 | Container image uses `:latest` or no tag | Medium | High |
| TRUST-AZP004 | Pipeline uses self-hosted pool | Low | Medium |
| TRUST-AZP005 | Pipeline publishes broad artifact path | Low | Medium |

### CircleCI

**Analyzer:** `CircleCiAnalyzer` (`circleci`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CIRCLE001 | CircleCI orb version is not pinned | Medium | High |
| TRUST-CIRCLE002 | Docker executor image uses `:latest` or no tag | Medium | High |
| TRUST-CIRCLE003 | Workspace persist stores repository root | Low | Medium |
| TRUST-CIRCLE004 | Inline secret-looking environment variable | High | Medium |
| TRUST-CIRCLE005 | Remote Docker enabled without explicit version | Low | Medium |

---

## Containers Analyzers

### Docker

**Analyzer:** `DockerBasicAnalyzer` (`docker-basic`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-DOCKER001 | Dockerfile exists but `.dockerignore` is missing | Medium | High |
| TRUST-DOCKER002 | Docker base image uses `:latest` tag | Medium | High |
| TRUST-DOCKER003 | Dockerfile does not declare a non-root USER | Medium | High |
| TRUST-DOCKER004 | Dockerfile does not declare HEALTHCHECK | Low | High |
| TRUST-DOCKER005 | Dockerfile may define secret-like ENV | High | Medium |
| TRUST-DOCKER006 | Dockerfile does not appear to use multi-stage build | Low | Medium |
| TRUST-DOCKER007 | Dockerfile copies entire context before dependency restore | Low | Medium |
| TRUST-DOCKER008 | Dockerfile separates apt-get update from install | Low | Medium |
| TRUST-DOCKER009 | Dockerfile uses ADD instead of COPY | Low | High |
| TRUST-DOCKER010 | Dockerfile uses sudo | High | High |
| TRUST-DOCKER011 | Dockerfile EXPOSE uses overly broad port range | Low | Medium |

### Docker Compose

**Analyzer:** `DockerComposeAnalyzer` (`docker-compose`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-COMP001 | Service runs in privileged mode | High | High |
| TRUST-COMP002 | Service uses host network mode | Medium | High |
| TRUST-COMP003 | Service mounts host directory | Medium | Medium |
| TRUST-COMP004 | Service exposes broad port range | Low | High |
| TRUST-COMP005 | Service may define secrets in environment | High | Medium |
| TRUST-COMP006 | Service mounts Docker socket | Critical | High |
| TRUST-COMP007 | Service loads `.env`-like file | Medium | Medium |

### Kubernetes

**Analyzer:** `KubernetesAnalyzer` (`kubernetes-security`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-K8S001 | Container runs in privileged mode | High | High |
| TRUST-K8S002 | Pod shares host namespace | High | High |
| TRUST-K8S003 | Container may run as root | Medium | High |
| TRUST-K8S004 | Container has writable root filesystem | Low | High |
| TRUST-K8S005 | Secret manifest in repository | Medium | High |
| TRUST-K8S006 | Manifest uses hostPath volume | High | High |
| TRUST-K8S007 | Container adds broad Linux capabilities | High | High |
| TRUST-K8S008 | Container allows privilege escalation | Medium | High |

---

## Infrastructure Analyzers

### Terraform

**Analyzer:** `TerraformAnalyzer` (`terraform`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-TF001 | Public ingress from the internet | High | Medium |
| TRUST-TF002 | Wildcard IAM action and resource | High | Medium |
| TRUST-TF003 | S3 bucket public ACL | High | High |
| TRUST-TF004 | S3 bucket encryption not visible | Medium | Low |
| TRUST-TF005 | Provider version constraint missing | Medium | Medium |
| TRUST-TF006 | S3 backend lacks encryption | Low | Medium |

---

## Dependencies Analyzers

### Dependency Inventory

**Analyzer:** `DependencyInventoryAnalyzer` (`dependency-inventory`)

Collects structured dependency manifests across 12 ecosystems: npm, NuGet, Python (pip/Pipenv/Poetry), Maven/Gradle, Go, Cargo, Composer, Ruby/Bundler, Dart/Pub, Elixir/Hex, SwiftPM, C/C++ (Conan/vcpkg/CMake).

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-DEP001 | npm manifest exists without lockfile | Medium | High |
| TRUST-DEP002 | NuGet project does not use lockfile | Low | Medium |
| TRUST-DEP003 | Python manifest has no recognized lockfile | Low | Medium |
| TRUST-DEP004 | NuGet dependency uses floating or unpinned version | Medium | High |
| TRUST-DEP005 | NuGet dependency uses prerelease version | Low | High |
| TRUST-DEP006 | npm dependency uses range or unpinned version | Medium | High |
| TRUST-DEP007 | npm dependency uses prerelease version | Low | High |
| TRUST-DEP008 | npm install-time script requires review | Medium | Medium |
| TRUST-DEP009 | Python requirement is unpinned | Medium | High |
| TRUST-DEP010 | Python dependency uses prerelease version | Low | High |
| TRUST-DEP011 | npm dependency uses direct remote source | Medium | High |
| TRUST-DEP012 | npm dependency uses local file source | Low | High |
| TRUST-DEP013 | NuGet package source uses insecure transport | High | High |
| TRUST-DEP014 | NuGet package source uses local path | Low | Medium |
| TRUST-DEP015 | Dependency appears outdated | Medium | Medium |
| TRUST-DEP016 | Dependency package is deprecated or yanked | High | High |
| TRUST-DEP017 | Java manifest without recognized lockfile | Low | Medium |
| TRUST-DEP018 | Java uses unpinned/dynamic dependency | Medium | High |
| TRUST-DEP019 | Java uses SNAPSHOT dependency | Low | High |
| TRUST-DEP020 | Gradle wrapper is missing | Low | Medium |
| TRUST-DEP021 | Spring Boot Actuator exposes broad endpoint access | High | Medium |
| TRUST-DEP022 | Go module has no go.sum lockfile | Medium | High |
| TRUST-DEP023 | Go module uses replace directive | Low | High |
| TRUST-DEP024 | Go dependency uses non-exact version | Medium | High |
| TRUST-DEP025 | Direct Go dependency uses pseudo-version | Low | High |
| TRUST-DEP026 | Cargo has no Cargo.lock | Medium | High |
| TRUST-DEP027 | Cargo dependency uses Git source | Medium | High |
| TRUST-DEP028 | Cargo dependency uses path source | Low | High |
| TRUST-DEP029 | Cargo dependency uses non-exact version without lockfile | Medium | High |
| TRUST-DEP030 | Cargo dependency uses prerelease version | Low | High |
| TRUST-DEP031 | Composer has no composer.lock | Medium | High |
| TRUST-DEP032 | Composer dependency uses non-exact version | Medium | High |
| TRUST-DEP033 | Composer dependency uses prerelease version | Low | High |
| TRUST-DEP034 | Ruby has no Gemfile.lock | Medium | High |
| TRUST-DEP035 | Ruby gem uses non-exact version | Medium | High |
| TRUST-DEP036 | Ruby gem uses Git/path dependency | Medium | High |
| TRUST-DEP037 | Dart project has no pubspec.lock | Medium | High |
| TRUST-DEP038 | Dart dependency uses non-exact version | Medium | High |
| TRUST-DEP040 | Elixir has no mix.lock | Medium | High |
| TRUST-DEP041 | Elixir dependency uses non-exact version | Medium | High |
| TRUST-DEP042 | Elixir dependency uses non-Hex source | Medium | High |
| TRUST-DEP043 | Swift package has no Package.resolved | Medium | High |
| TRUST-DEP044 | Swift uses branch-based dependency | Medium | High |
| TRUST-DEP046 | C/C++ uses Conan package manager | Low | High |
| TRUST-DEP047 | C/C++ uses vcpkg | Low | High |
| TRUST-DEP048 | C/C++ uses CMake external dependencies | Low | High |
| TRUST-DEP049 | Ruby gem uses prerelease version | Low | High |
| TRUST-DEP050 | Gradle version catalog uses dynamic dependency version | Medium | High |
| TRUST-DEP051 | Gradle version catalog uses dynamic plugin version | Medium | High |

### Dependency Risk Intelligence

**Analyzer:** `DependencyRiskAnalyzer` (`dependency-risk`)

**Freshness:**

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-DEP015 | Dependency appears outdated | Medium | Medium |
| TRUST-DEP016 | Dependency package is deprecated or yanked | High | High |

**Vulnerabilities:**

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-VULN001 | Direct dependency has a known vulnerability | High | High |
| TRUST-VULN002 | Transitive dependency has a known vulnerability | Medium | Medium |
| TRUST-VULN003 | Vulnerable dependency has a known fixed version | Info | High |

**Licenses:**

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-LIC001 | Dependency license is unknown | Low | Medium |
| TRUST-LIC002 | Dependency uses a policy-sensitive license | Medium | Medium |
| TRUST-LIC003 | Package license metadata is missing | Low | High |

### Package Origin

**Analyzer:** `PackageOriginAnalyzer` (`package-origin`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-ORIGIN001 | Package repository URL does not match scanned repo | Medium | Medium |
| TRUST-ORIGIN002 | Official-looking name from unverified origin | Low | Low |
| TRUST-ORIGIN003 | Package origin metadata is incomplete | Low | Medium |
| TRUST-ORIGIN004 | Package source mapping missing for mixed NuGet sources | Medium | Medium |
| TRUST-ORIGIN005 | npm scope registry configuration appears risky | Medium | Medium |
| TRUST-ORIGIN006 | Internal-looking package resolved from public registry | Medium | Medium |

### Package Registry Configuration

**Analyzer:** `PackageRegistryConfigAnalyzer` (`package-registry-config`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-REG001 | Package registry uses HTTP | High | High |
| TRUST-REG002 | npm `always-auth` enabled globally | Medium | Medium |
| TRUST-REG003 | Inline package registry token | High | Medium |
| TRUST-REG004 | Maven mirror redirects all repositories | Medium | Medium |
| TRUST-REG005 | Gradle allows insecure protocol | High | High |

---

## Security Analyzers

### Secret Quick Scan

**Analyzer:** `SecretQuickScanAnalyzer` (`secret-quick-scan`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-SECRET001 | Sensitive-looking file is committed | High | High |
| TRUST-SECRET002 | Possible private key marker found | Critical | High |
| TRUST-SECRET003 | Possible GitHub token found | High | Medium |
| TRUST-SECRET004 | Possible AWS access key found | High | Medium |
| TRUST-SECRET005 | Possible database connection string found | High | Medium |
| TRUST-SECRET006 | Possible Slack webhook found | High | Medium |
| TRUST-SECRET007 | Possible Discord webhook found | High | Medium |
| TRUST-SECRET008 | Possible Azure connection string or storage key found | High | Medium |
| TRUST-SECRET009 | Possible GCP service account key found | High | Medium |
| TRUST-SECRET010 | Possible JWT token found | Medium | Medium |
| TRUST-SECRET011 | Possible registry token found | High | Medium |
| TRUST-SECRET012 | Possible generic API key found | Medium | Low |

---

## Releases Analyzers

### Release Evidence

**Analyzer:** `ReleaseEvidenceAnalyzer` (`release-evidence`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-REL001 | Changelog does not mention detected package version | Low | Medium |
| TRUST-REL002 | Release artifact lacks checksum evidence | Medium | Medium |
| TRUST-REL003 | Release artifact lacks SBOM/provenance evidence | Low | Medium |
| TRUST-REL005 | Release workflow lacks integrity evidence steps | Medium | Medium |
| TRUST-REL005 | Release workflow lacks integrity evidence steps | Medium | Medium |

### Evidence Import

**Analyzer:** `EvidenceImportAnalyzer` (`evidence-import`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-EVI001 | SBOM evidence found in repository | Info | High |
| TRUST-EVI003 | Provenance evidence found in repository | Info | High |
| TRUST-EVI004 | SBOM evidence file is not parseable | Medium | High |
| TRUST-EVI005 | SBOM evidence appears empty | Low | Medium |
| TRUST-EVI006 | Provenance evidence file is not parseable | Medium | High |
| TRUST-EVI007 | SBOM appears potentially incomplete | Low | Medium |
| TRUST-EVI008 | SBOM package URL is malformed | Low | High |
| TRUST-EVI009 | Evidence metadata target differs from scanned repo | Medium | Medium |

---

## Codebase Analyzers

### Coverage Import

**Analyzer:** `CoverageImportAnalyzer` (`codebase-01-coverage-import`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE001 | Coverage report was not found | Info | High |
| TRUST-CODE002 | Imported coverage is below the recommended baseline | Medium | Medium |
| TRUST-CODE003 | Coverage report could not be parsed | Low | High |

### Code Criticality

**Analyzer:** `CodeCriticalityAnalyzer` (`codebase-02-criticality`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE004 | Security-sensitive code area was detected | Medium | Medium |
| TRUST-CODE005 | Large critical source file was detected | Low | Medium |
| TRUST-CODE006 | Broad exception handling in critical code | Medium | Medium |
| TRUST-CODE014 | Deserialization in critical code | High | Medium |
| TRUST-CODE015 | Command execution in critical code | High | Medium |

### Coverage Criticality

**Analyzer:** `CoverageCriticalityAnalyzer` (`codebase-03-coverage-criticality`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE007 | Critical code has low or missing coverage | High | Medium |

### Public API

**Analyzer:** `PublicApiAnalyzer` (`codebase-04-public-api`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE008 | Public API surface has changed | Medium | Medium |
| TRUST-CODE009 | New public API member is not documented | Low | Medium |

### Import Graph

**Analyzer:** `ImportGraphAnalyzer` (`codebase-05-import-graph`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE010 | Highly central file detected | Low | Medium |
| TRUST-CODE011 | Central file with low or missing coverage | Medium | Medium |

### Framework Routes

**Analyzer:** `FrameworkRouteAnalyzer` (`codebase-06-framework-routes`)

| Rule ID | Title | Severity | Confidence |
|---------|-------|----------|------------|
| TRUST-CODE012 | HTTP endpoint without authentication | High | Medium |
| TRUST-CODE013 | Informational route endpoint detected | Info | High |

---

## Rule ID Prefix Reference

| Prefix | Category | Analyzer |
|--------|----------|----------|
| `TRUST-REPO` | Repository Health | RepositoryHealthAnalyzer |
| `TRUST-WS` | Repository Health | WorkspaceAnalyzer |
| `TRUST-GHA` | CiCd | GitHubActionsBasicAnalyzer |
| `TRUST-GLCI` | CiCd | GitLabCiAnalyzer |
| `TRUST-AZP` | CiCd | AzurePipelinesAnalyzer |
| `TRUST-CIRCLE` | CiCd / Security | CircleCiAnalyzer |
| `TRUST-DOCKER` | Containers | DockerBasicAnalyzer |
| `TRUST-COMP` | Containers | DockerComposeAnalyzer |
| `TRUST-K8S` | Containers | KubernetesAnalyzer |
| `TRUST-TF` | Infrastructure | TerraformAnalyzer |
| `TRUST-DEP` | Dependencies | DependencyInventoryAnalyzer / DependencyRiskAnalyzer |
| `TRUST-VULN` | Dependencies | DependencyRiskAnalyzer |
| `TRUST-LIC` | Licenses | DependencyRiskAnalyzer |
| `TRUST-ORIGIN` | Dependencies | PackageOriginAnalyzer |
| `TRUST-REG` | Dependencies | PackageRegistryConfigAnalyzer |
| `TRUST-SECRET` | Security | SecretQuickScanAnalyzer |
| `TRUST-REL` | Releases | ReleaseEvidenceAnalyzer |
| `TRUST-EVI` | Releases | EvidenceImportAnalyzer |
| `TRUST-CODE` | Codebase | CoverageImport / CodeCriticality / CoverageCriticality / PublicApi / ImportGraph / FrameworkRoute |
