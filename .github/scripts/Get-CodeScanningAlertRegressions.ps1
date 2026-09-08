<#
.SYNOPSIS
    Checks all repositories the mu88-bot app is installed on for open CodeQL code
    scanning alerts, and reports newly-detected ones.

.DESCRIPTION
    Repositories to check are discovered dynamically via the GitHub App installation
    (no hardcoded repo list), so newly onboarded repos are covered automatically.

    For each repository, all currently open code scanning alerts are fetched. Alerts
    are tracked in a small JSON state file (persisted by the caller via actions/cache,
    not via git commits), keyed by "owner/repo#alert-number", so an alert is only
    flagged once, until either it is fixed/dismissed (dropping out of state) or it
    reappears (e.g. reopened), in which case it is reported as new again. State
    entries for alerts that are no longer open are pruned on every run.

    Repositories without any code scanning analysis at all (CodeQL never ran, e.g. a
    repo not yet wired up to the shared gha-checks.yml workflow) are skipped
    informationally - this is expected for some repos and not a failure.

    Any other error while querying a repository (e.g. missing "Code scanning alerts"
    permission on the GitHub App installation) is surfaced and fails the job, rather
    than being silently swallowed and reported as "no new alerts".
#>
param(
    [Parameter(Mandatory)] [string] $Token,
    [Parameter(Mandatory)] [string] $StateFilePath,
    [string] $SummaryFile = $env:GITHUB_STEP_SUMMARY
)

$ErrorActionPreference = 'Stop'
$env:GH_TOKEN = $Token

function Invoke-GhApi([string[]] $Arguments) {
    # Merge stderr into the output so real failures are visible in the exception
    # message instead of being discarded; $LASTEXITCODE is the authoritative
    # success signal for native commands (PowerShell won't throw on its own).
    $output = & gh @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh $($Arguments -join ' ') failed with exit code ${LASTEXITCODE}: $output"
    }
    $output
}

function Test-NoAnalysisFoundError([string] $ErrorMessage) {
    # GitHub returns 404 with this message for repos that have never had a
    # successful CodeQL analysis - expected for some repos, not a real failure.
    $ErrorMessage -match 'no analysis found' -or $ErrorMessage -match 'HTTP 404'
}

function Get-PreviousState([string] $Path) {
    $state = @{}
    if (Test-Path $Path) {
        $raw = Get-Content $Path -Raw
        if ($raw) {
            (ConvertFrom-Json $raw).PSObject.Properties | ForEach-Object { $state[$_.Name] = [string]$_.Value }
        }
    }
    $state
}

function Get-InstalledRepositories {
    Invoke-GhApi @('api', '/installation/repositories', '--paginate', '--jq', '.repositories[].full_name')
}

function Get-OpenCodeScanningAlerts([string] $Repo) {
    $json = Invoke-GhApi @(
        'api', "repos/$Repo/code-scanning/alerts?state=open&per_page=100", '--paginate',
        '--jq', '[.[] | { number, rule_id: .rule.id, severity: .rule.severity, html_url, created_at }]'
    )
    @($json | ConvertFrom-Json)
}

# --- Main ---
$previousState = Get-PreviousState $StateFilePath
$newState = @{}
$newAlerts = [System.Collections.Generic.List[object]]::new()
$checkErrors = [System.Collections.Generic.List[string]]::new()
$skippedRepos = [System.Collections.Generic.List[string]]::new()

$repos = @(Get-InstalledRepositories)
Write-Host "Discovered $($repos.Count) installed repositories."

foreach ($repo in $repos) {
    try {
        $alerts = @(Get-OpenCodeScanningAlerts $repo)
    } catch {
        if (Test-NoAnalysisFoundError $_.Exception.Message) {
            Write-Host "${repo}: no code scanning analysis found, skipping"
            $skippedRepos.Add($repo)
            continue
        }
        $message = "Failed to check code scanning alerts for ${repo}: $_"
        Write-Host "::error::$message"
        $checkErrors.Add($message)
        continue
    }

    Write-Host "${repo}: $($alerts.Count) open alert(s)"

    foreach ($alert in $alerts) {
        $key = "$repo#$($alert.number)"
        $newState[$key] = [string]$alert.number

        if (-not $previousState.ContainsKey($key)) {
            $newAlerts.Add([PSCustomObject]@{
                Repo     = $repo
                Number   = $alert.number
                RuleId   = $alert.rule_id
                Severity = $alert.severity
                Url      = $alert.html_url
            })
        }
    }
}

# $newState only contains keys for alerts observed as open this run; entries for
# alerts that are fixed/dismissed (no longer open) are pruned automatically since
# no path ever re-adds a key for them.
$newState | ConvertTo-Json | Out-File $StateFilePath -Encoding utf8

if ($skippedRepos.Count -gt 0) {
    '## ℹ️ Repositories without code scanning analysis (skipped)' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    foreach ($skipped in $skippedRepos) { "- ``$skipped``" | Out-File -Append $SummaryFile }
    '' | Out-File -Append $SummaryFile
}

if ($checkErrors.Count -gt 0) {
    '## ⚠️ Errors while checking repositories' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    foreach ($checkError in $checkErrors) { "- $checkError" | Out-File -Append $SummaryFile }
    '' | Out-File -Append $SummaryFile
}

if ($newAlerts.Count -gt 0) {
    '## 🔴 New CodeQL alerts detected' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    '| Repo | # | Rule | Severity | Alert |' | Out-File -Append $SummaryFile
    '| --- | --- | --- | --- | --- |' | Out-File -Append $SummaryFile
    foreach ($alert in $newAlerts) {
        "| [``$($alert.Repo)``](https://github.com/$($alert.Repo)) | $($alert.Number) | $($alert.RuleId) | $($alert.Severity) | [Alert]($($alert.Url)) |" |
            Out-File -Append $SummaryFile
    }
}

if ($checkErrors.Count -gt 0 -or $newAlerts.Count -gt 0) { exit 1 }

'## ✅ No new CodeQL alerts' | Out-File -Append $SummaryFile
