# Quality Validation

Repository Trust Doctor quality work should use repeatable large-repository scans, small synthetic regression fixtures, and rule-count diffs.

## Benchmark Corpus

Use a rotating corpus of large public repositories that stress different ecosystems:

| Ecosystem focus | Example repositories |
| --- | --- |
| JavaScript / TypeScript | `microsoft/vscode`, `storybookjs/storybook` |
| Java / Gradle / Maven | `elastic/elasticsearch`, `spring-projects/spring-boot` |
| Go / Terraform | `kubernetes/kubernetes`, `hashicorp/terraform` |
| Python | `ansible/ansible`, `apache/airflow` |
| Dart / Flutter | `flutter/flutter` |
| Rust | `rust-lang/rust`, `denoland/deno` |
| Multi-language platform | `grafana/grafana`, `home-assistant/core` |

Avoid relying on one repository family. A good validation pass includes at least one dependency-heavy repository, one CI-heavy repository, one infrastructure-heavy repository, and one framework repository with many tests/examples.

## Scan Matrix

Run deep scans with mixed profiles so profile-specific scoring and policy behavior are exercised:

```powershell
dotnet build src\Apps\RepoTrustDoctor.Cli\RepoTrustDoctor.Cli.csproj

$cli = "src\Apps\RepoTrustDoctor.Cli\bin\Debug\net10.0\RepoTrustDoctor.Cli.dll"
$out = "$env:TEMP\repo-trust-quality-current"
New-Item -ItemType Directory -Force -Path $out | Out-Null

dotnet $cli scan https://github.com/microsoft/vscode --depth deep --profile production --format json --output "$out\vscode.json" --force
dotnet $cli scan https://github.com/hashicorp/terraform --depth deep --profile security --format json --output "$out\terraform.json" --force
dotnet $cli scan https://github.com/ansible/ansible --depth deep --profile production --format json --output "$out\ansible.json" --force
dotnet $cli scan https://github.com/elastic/elasticsearch --depth deep --profile security --format json --output "$out\elasticsearch.json" --force
dotnet $cli scan https://github.com/flutter/flutter --depth deep --profile personal --format json --output "$out\flutter.json" --force
```

The CLI may return exit code `3` when a repository is classified as `AvoidAsProductionDependency`. Treat that as a completed scan when the JSON report exists.

For repeated false-positive and performance work, keep shallow local clones under the ignored `.repo-trust/corpus` directory and scan those local paths instead of cloning from GitHub every run:

```powershell
$corpus = ".repo-trust\corpus"
New-Item -ItemType Directory -Force -Path $corpus | Out-Null

git clone --depth 1 https://github.com/django/django.git "$corpus\django"
git clone --depth 1 https://github.com/rails/rails.git "$corpus\rails"
git clone --depth 1 https://github.com/spring-projects/spring-framework.git "$corpus\spring-framework"
git clone --depth 1 https://github.com/hashicorp/terraform.git "$corpus\terraform"
git clone --depth 1 https://github.com/kubernetes/kubernetes.git "$corpus\kubernetes"
git clone --depth 1 https://github.com/laravel/framework.git "$corpus\laravel-framework"
git clone --depth 1 https://github.com/flutter/flutter.git "$corpus\flutter"
git clone --depth 1 https://github.com/ansible/ansible.git "$corpus\ansible"

dotnet $cli scan "$corpus\terraform" --depth deep --profile production --format json --output "$out\terraform.json" --force
```

Local corpus scans should still use multiple ecosystems and profiles. The scanner prunes repository metadata, dependency cache directories, vendored code directories, and private ignored workspaces during enumeration. Deep scans build a per-scan file index so repeated analyzer file searches do not repeatedly walk the same large repository tree.

For very large repositories, codebase analyzers should prefer `CompletedWithWarnings` plus explicit truncation metrics over hard timeouts. Review `*.modules[*].status`, `*.modules[*].errorMessage`, and analyzer metrics after each corpus run; a timeout is usually a product issue, while a warning with source/analyzed counts is an explainable scope limit.

Deep code analyzers use deterministic partition-balanced selection when a repository exceeds the 6,000-file budget. Monorepo roots such as `packages`, `apps`, `services`, `modules`, and `crates` are sampled round-robin instead of taking one alphabetical prefix. Review each analyzer's `partition.count` and `selected_partition.count` metrics together with analyzed/source file counts.

For dependency validation, inspect `dependency.package.lock-resolved.count` and sample the resolved package records. npm ranges can resolve through `package-lock.json` v1-v3, including workspace-specific package entries. NuGet projects resolve only through an adjacent `packages.lock.json`; conflicting versions across target frameworks remain unresolved instead of being collapsed to an arbitrary version. Both readers accept lockfiles up to 64 MiB through bounded JSON parsing.

For repeated network-intelligence benchmarks, also record:

- `dependency.metadata.cache.hit.count`
- `dependency.metadata.network.count`
- `dependency.vulnerability.lookup.local.count`
- `dependency.vulnerability.lookup.online.count`

Use a fresh dedicated SQLite database to measure cold behavior, then repeat against the same database to measure warm behavior. Do not compare a cold scan with a warm scan without labeling the cache state.

Measure analyzer performance with a solo run before treating a concurrent-run timeout as an algorithmic regression. Parallel scans are still useful for cancellation and resource-contention validation, but registry latency, disk contention, and CPU pressure make their wall-clock durations unsuitable as a stable baseline.

## Rule Distribution Diffs

Summarize a current report directory:

```powershell
.\tools\quality\Compare-ScanReports.ps1 -Current "$env:TEMP\repo-trust-quality-current"
```

Compare a new run against a saved baseline:

```powershell
.\tools\quality\Compare-ScanReports.ps1 `
  -Baseline "$env:TEMP\repo-trust-quality-baseline" `
  -Current "$env:TEMP\repo-trust-quality-current" `
  -Top 20
```

Review the largest rule-count deltas first. A high-volume drop is good only when the removed findings were genuinely low-signal examples, fixtures, generated files, or parser mistakes. A high-volume increase needs evidence review before being accepted.

## Triage Rules

- Fix parser mistakes with small synthetic regression tests before changing severity or scoring.
- Prefer path classification for examples, fixtures, tests, generated files, and documentation over per-rule ad hoc string checks.
- Do not suppress a rule globally because one large repository is noisy.
- Keep inventory artifacts even when a finding is suppressed; downstream analyzers still need dependency evidence.
- For false negatives, create a minimal fixture that proves the missing risky pattern is detected.
- For false positives, include both the noisy real-world path shape and a positive control that still reports the real issue.

## Commit Shape

Quality commits should stay small:

- one commit for shared classification or analyzer infrastructure,
- one commit per rule-family behavior change,
- one commit for docs/scripts when the workflow changes.

Run `dotnet test RepoTrustDoctor.slnx` before pushing quality changes.
