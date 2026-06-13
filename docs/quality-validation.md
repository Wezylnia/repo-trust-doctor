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
