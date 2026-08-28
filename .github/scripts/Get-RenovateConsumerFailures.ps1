<#
.SYNOPSIS
    Checks all repositories the Renovate bot app is installed on for failing CI runs on
    active `renovate/*` branches, and reports newly-detected failures.

.DESCRIPTION
    Repositories to check are discovered dynamically via the GitHub App installation
    (no hardcoded repo list), so newly onboarded repos are covered automatically.

    For each `renovate/*` branch, the latest completed run of every workflow that
    triggered on that branch is inspected (not just the single most recently created run),
    so a failure in a secondary workflow isn't masked by an unrelated, newer, successful one.

    Already-reported failures are tracked in a small JSON state file (persisted by the
    caller via actions/cache, not via git commits) so that a failure is only flagged once,
    until either the branch is fixed/removed or a new failing run appears. State entries
    for branches that no longer exist are pruned on every run.

    Any error while querying a repository (e.g. missing permissions) is surfaced and fails
    the job, rather than being silently swallowed and reported as "no failures".
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

function Get-RenovateBranches([string] $Repo) {
    Invoke-GhApi @('api', "repos/$Repo/branches", '--paginate', '--jq', '.[].name') |
        Where-Object { $_ -like 'renovate/*' }
}

function Get-LatestFailingRun([string] $Repo, [string] $Branch) {
    # Look at more than the single latest run: a branch can trigger several
    # workflows (e.g. CI + a linter) on the same push, and only checking the
    # most recently created run could miss a failure in a sibling workflow.
    # No `event=` filter, so this also covers repos whose CI only triggers on
    # `pull_request` once Renovate opens a PR for the branch.
    $encodedBranch = [System.Uri]::EscapeDataString($Branch)
    $json = Invoke-GhApi @(
        'api', "repos/$Repo/actions/runs?branch=$encodedBranch&status=completed&per_page=20",
        '--jq', '.workflow_runs'
    )
    $runs = $json | ConvertFrom-Json
    if (-not $runs -or $runs.Count -eq 0) { return $null }

    $latestPerWorkflow = $runs |
        Sort-Object -Property created_at -Descending |
        Group-Object -Property workflow_id |
        ForEach-Object { $_.Group[0] }

    $latestPerWorkflow | Where-Object { $_.conclusion -eq 'failure' } | Select-Object -First 1
}

# --- Main ---
$previousState = Get-PreviousState $StateFilePath
$newState = @{}
$newFailures = [System.Collections.Generic.List[object]]::new()
$checkErrors = [System.Collections.Generic.List[string]]::new()

$repos = @(Get-InstalledRepositories)
Write-Host "Discovered $($repos.Count) installed repositories."

foreach ($repo in $repos) {
    try {
        $branches = @(Get-RenovateBranches $repo)
    } catch {
        $message = "Failed to list branches for ${repo}: $_"
        Write-Host "::error::$message"
        $checkErrors.Add($message)
        continue
    }

    if ($branches.Count -gt 0) {
        Write-Host "${repo}: found renovate branch(es) $($branches -join ', ')"
    }

    foreach ($branch in $branches) {
        $key = "$repo#$branch"
        try {
            $failingRun = Get-LatestFailingRun $repo $branch
        } catch {
            $message = "Failed to check runs for ${repo}:${branch}: $_"
            Write-Host "::error::$message"
            $checkErrors.Add($message)
            continue
        }

        if (-not $failingRun) {
            Write-Host "${repo}:${branch}: no failing run found"
            continue
        }

        Write-Host "${repo}:${branch}: latest failing run is $($failingRun.id) ($($failingRun.html_url))"
        $newState[$key] = [string]$failingRun.id
        if ($previousState[$key] -ne [string]$failingRun.id) {
            $newFailures.Add([PSCustomObject]@{ Repo = $repo; Branch = $branch; Url = $failingRun.html_url })
        }
    }
}

# $newState only contains keys for branches observed in this run, so entries
# for deleted/merged Renovate branches are pruned automatically.
$newState | ConvertTo-Json | Out-File $StateFilePath -Encoding utf8

if ($checkErrors.Count -gt 0) {
    '## ⚠️ Errors while checking repositories' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    foreach ($checkError in $checkErrors) { "- $checkError" | Out-File -Append $SummaryFile }
    '' | Out-File -Append $SummaryFile
}

if ($newFailures.Count -gt 0) {
    '## 🔴 New Renovate CI failures detected' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    '| Repo | Branch | Run |' | Out-File -Append $SummaryFile
    '| --- | --- | --- |' | Out-File -Append $SummaryFile
    foreach ($failure in $newFailures) {
        "| [``$($failure.Repo)``](https://github.com/$($failure.Repo)) | ``$($failure.Branch)`` | [Run]($($failure.Url)) |" |
            Out-File -Append $SummaryFile
    }
}

if ($checkErrors.Count -gt 0 -or $newFailures.Count -gt 0) { exit 1 }

'## ✅ No new Renovate CI failures' | Out-File -Append $SummaryFile
