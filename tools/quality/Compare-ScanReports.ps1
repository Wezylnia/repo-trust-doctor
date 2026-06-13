param(
    [Parameter(Mandatory = $true)]
    [string[]] $Current,

    [string[]] $Baseline = @(),

    [int] $Top = 15
)

$ErrorActionPreference = "Stop"

function Expand-ReportPath {
    param([string[]] $Paths)

    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path -PathType Container) {
            Get-ChildItem -LiteralPath $path -Filter "*.json" | ForEach-Object { $_.FullName }
        }
        elseif (Test-Path -LiteralPath $path -PathType Leaf) {
            (Resolve-Path -LiteralPath $path).Path
        }
        else {
            throw "Report path does not exist: $path"
        }
    }
}

function Read-ScanReport {
    param([string] $Path)

    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $findings = @($json.findings)
    $decision = $json.decision
    if ($null -ne $json.decision.status) {
        $decision = $json.decision.status
    }

    $ruleCounts = @{}
    foreach ($finding in $findings) {
        $ruleId = [string] $finding.ruleId
        if ([string]::IsNullOrWhiteSpace($ruleId)) {
            $ruleId = "<missing-rule>"
        }

        if (-not $ruleCounts.ContainsKey($ruleId)) {
            $ruleCounts[$ruleId] = 0
        }
        $ruleCounts[$ruleId]++
    }

    [pscustomobject]@{
        Name = [IO.Path]::GetFileNameWithoutExtension($Path)
        Path = $Path
        Score = [int] $json.score.overall
        Decision = [string] $decision
        Findings = $findings.Count
        RuleCounts = $ruleCounts
    }
}

function Write-ReportSummary {
    param([object[]] $Reports)

    $Reports |
        Sort-Object Name |
        Select-Object Name, Score, Findings, Decision, Path |
        Format-Table -AutoSize

    foreach ($report in ($Reports | Sort-Object Name)) {
        ""
        "Top rules for $($report.Name)"
        $report.RuleCounts.GetEnumerator() |
            Sort-Object -Property @{ Expression = "Value"; Descending = $true }, Name |
            Select-Object -First $Top @{ Name = "Count"; Expression = { $_.Value } }, @{ Name = "RuleId"; Expression = { $_.Name } } |
            Format-Table -AutoSize
    }
}

function Write-ReportDiff {
    param(
        [object[]] $BaselineReports,
        [object[]] $CurrentReports
    )

    $baselineByName = @{}
    foreach ($report in $BaselineReports) {
        $baselineByName[$report.Name] = $report
    }

    foreach ($currentReport in ($CurrentReports | Sort-Object Name)) {
        if (-not $baselineByName.ContainsKey($currentReport.Name)) {
            "No baseline report found for $($currentReport.Name)."
            continue
        }

        $baselineReport = $baselineByName[$currentReport.Name]
        ""
        "Diff for $($currentReport.Name)"
        [pscustomobject]@{
            BaselineScore = $baselineReport.Score
            CurrentScore = $currentReport.Score
            ScoreDelta = $currentReport.Score - $baselineReport.Score
            BaselineFindings = $baselineReport.Findings
            CurrentFindings = $currentReport.Findings
            FindingDelta = $currentReport.Findings - $baselineReport.Findings
        } | Format-Table -AutoSize

        $allRuleIds = [string[]] @($baselineReport.RuleCounts.Keys + $currentReport.RuleCounts.Keys | Sort-Object -Unique)
        $allRuleIds |
            ForEach-Object {
                $ruleId = $_
                $before = if ($baselineReport.RuleCounts.ContainsKey($ruleId)) { $baselineReport.RuleCounts[$ruleId] } else { 0 }
                $after = if ($currentReport.RuleCounts.ContainsKey($ruleId)) { $currentReport.RuleCounts[$ruleId] } else { 0 }
                [pscustomobject]@{
                    RuleId = $ruleId
                    Baseline = $before
                    Current = $after
                    Delta = $after - $before
                }
            } |
            Where-Object { $_.Delta -ne 0 } |
            Sort-Object -Property @{ Expression = { [Math]::Abs($_.Delta) }; Descending = $true }, RuleId |
            Select-Object -First $Top |
            Format-Table -AutoSize
    }
}

$currentReports = @(Expand-ReportPath $Current | ForEach-Object { Read-ScanReport $_ })
if ($Baseline.Count -eq 0) {
    Write-ReportSummary $currentReports
    exit 0
}

$baselineReports = @(Expand-ReportPath $Baseline | ForEach-Object { Read-ScanReport $_ })
Write-ReportDiff $baselineReports $currentReports
