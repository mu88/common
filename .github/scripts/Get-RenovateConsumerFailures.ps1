<#
.SYNOPSIS
    Checks all repositories the Renovate bot app is installed on for failing CI runs on
    active `renovate/*` branches, and reports newly-detected failures.

.DESCRIPTION
    Repositories to check are discovered dynamically via the GitHub App installation
    (no hardcoded repo list), so newly onboarded repos are covered automatically.

    For each `renovate/*` branch, the latest completed run of every workflow that
    triggered for the branch's current head is inspected (not just the single most recently
    created run), so failures from superseded commits aren't reported as current failures.

    Already-reported failures are tracked in a small JSON state file (persisted by the
    caller via actions/cache, not via git commits) so that a failure is only flagged once,
    until either the branch is fixed/removed or a new failing run appears. State entries
    for branches that no longer exist are pruned on every run.

    Before checking branches, the script tries to download the "renovate-active-branches"
    artifact from the most recent completed run of mu88/common's own `renovate.yml`
    workflow (using the job's own GITHUB_TOKEN, not the cross-repo App token below). That
    artifact lists, per repository, the `renovate/*` branches Renovate currently actively
    tracks - which is used to skip branches that still exist on GitHub but are no longer
    tracked by Renovate (e.g. leftovers from a config change), without flagging them as CI
    failures. If the artifact is unavailable, stale (older than a generous freshness
    window), or fails to parse, this filtering is skipped entirely and every existing
    `renovate/*` branch is checked as before (fail-open: a missed alert is worse than an
    unnecessary check).

    Errors listing repositories or branches fail the job. If CI status cannot be tied to
    the current branch head, it is reported as unknown and prior failure state is preserved.
#>
param(
    [Parameter(Mandatory)] [string] $Token,
    [Parameter(Mandatory)] [string] $StateFilePath,
    [string] $SummaryFile = $env:GITHUB_STEP_SUMMARY
)

$ErrorActionPreference = 'Stop'
$env:GH_TOKEN = $Token
Import-Module (Join-Path $PSScriptRoot 'RenovateConsumerWatchdog.psm1') -Force

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

function Invoke-GhAsRepoToken([string[]] $Arguments) {
    # mu88/common's own Actions API/artifacts must be read with the workflow job's own
    # GITHUB_TOKEN, not the cross-repo App token ($env:GH_TOKEN is set to the App token
    # for the whole script's lifetime further down) - the App may not have access, and
    # this repo doesn't need it since the watchdog already runs inside mu88/common.
    $previousToken = $env:GH_TOKEN
    try {
        $env:GH_TOKEN = $env:GITHUB_TOKEN
        Invoke-GhApi $Arguments
    } finally {
        $env:GH_TOKEN = $previousToken
    }
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
    $json = Invoke-GhApi @(
        'api', "repos/$Repo/branches", '--paginate',
        '--jq', '[.[] | select(.name | startswith("renovate/")) | { name, sha: .commit.sha }]'
    )
    $json | ConvertFrom-Json
}

function Get-RenovateActiveBranchMap {
    # renovate.yml runs at least every 6h (worst case: non-Monday schedule), and this
    # watchdog runs twice a day - a 12h freshness window comfortably covers normal
    # scheduling gaps while still detecting a genuinely broken/disabled Renovate run.
    $freshnessLimit = (Get-Date).ToUniversalTime().AddHours(-12)

    try {
        $runsJson = Invoke-GhAsRepoToken @(
            'api', 'repos/mu88/common/actions/workflows/renovate.yml/runs?status=completed&per_page=5',
            '--jq', '[.workflow_runs[] | {id, run_started_at}] | sort_by(.run_started_at) | reverse'
        )
        $candidateRuns = @($runsJson | ConvertFrom-Json)
    } catch {
        return [PSCustomObject]@{ Available = $false; Reason = "Failed to list renovate.yml runs: $_" }
    }

    if ($candidateRuns.Count -eq 0) {
        return [PSCustomObject]@{ Available = $false; Reason = 'No completed renovate.yml run found.' }
    }

    foreach ($candidate in $candidateRuns) {
        $runStarted = [DateTime]::Parse($candidate.run_started_at, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        if ($runStarted -lt $freshnessLimit) {
            # Candidates are sorted newest-first, so every remaining one is even older.
            return [PSCustomObject]@{
                Available = $false
                Reason    = "Newest remaining renovate.yml run ($($candidate.id)) is older than the 12h freshness window (started $($candidate.run_started_at))."
            }
        }

        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "renovate-active-branches-$($candidate.id)"
        try {
            try {
                Invoke-GhAsRepoToken @(
                    'run', 'download', $candidate.id,
                    '--repo', 'mu88/common',
                    '--name', 'renovate-active-branches',
                    '--dir', $tempDir
                ) | Out-Null
            } catch {
                Write-Host "renovate.yml run $($candidate.id) has no usable active-branch artifact, trying older run. ($_)"
                continue
            }

            $artifactPath = Join-Path $tempDir 'renovate-active-branches.json'
            if (-not (Test-Path $artifactPath)) {
                Write-Host "renovate.yml run $($candidate.id) artifact did not contain the expected file, trying older run."
                continue
            }

            $parsed = Get-Content $artifactPath -Raw | ConvertFrom-Json
            if ($parsed.schemaVersion -ne 1) {
                Write-Host "renovate.yml run $($candidate.id) artifact has unexpected schema version '$($parsed.schemaVersion)', trying older run."
                continue
            }

            $map = @{}
            $parsed.repositories.PSObject.Properties | ForEach-Object { $map[$_.Name] = @($_.Value) }

            return [PSCustomObject]@{
                Available    = $true
                Repositories = $map
                RunId        = $candidate.id
                GeneratedAt  = $parsed.generatedAtUtc
            }
        } catch {
            Write-Host "Failed to use active-branch artifact from renovate.yml run $($candidate.id), trying older run. ($_)"
            continue
        } finally {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    [PSCustomObject]@{ Available = $false; Reason = 'No completed renovate.yml run within the freshness window produced a usable active-branch artifact.' }
}

function Get-RenovateRunQuery([string] $Endpoint, [switch] $Paginate) {
    if ($Paginate) {
        $json = Invoke-GhApi @('api', $Endpoint, '--paginate', '--slurp')
        $pages = @($json | ConvertFrom-Json)
        return [PSCustomObject]@{
            Runs       = @($pages | ForEach-Object { $_.workflow_runs })
            IsComplete = $true
        }
    }

    $json = Invoke-GhApi @('api', $Endpoint, '--jq', '{total_count, workflow_runs}')
    $response = $json | ConvertFrom-Json
    [PSCustomObject]@{
        Runs       = @($response.workflow_runs)
        IsComplete = $response.total_count -le @($response.workflow_runs).Count
    }
}

function Get-RenovateRunData([string] $Repo, [PSCustomObject] $Branch) {
    $encodedBranch = [System.Uri]::EscapeDataString($Branch.name)
    $encodedSha = [System.Uri]::EscapeDataString($Branch.sha)
    $headEndpoint = "repos/$Repo/actions/runs?branch=$encodedBranch&head_sha=$encodedSha&status=completed&per_page=100"
    $pullRequestEndpoint = "repos/$Repo/actions/runs?branch=$encodedBranch&event=pull_request&status=completed&per_page=100"
    $headQuery = Get-RenovateRunQuery -Endpoint $headEndpoint -Paginate
    $pullRequestQuery = Get-RenovateRunQuery -Endpoint $pullRequestEndpoint
    $runs = @($headQuery.Runs + $pullRequestQuery.Runs | Sort-Object -Property id, run_attempt -Unique)

    [PSCustomObject]@{
        Endpoint   = "$headEndpoint; $pullRequestEndpoint"
        Runs       = $runs
        IsComplete = $headQuery.IsComplete -and $pullRequestQuery.IsComplete
    }
}

function New-RenovateRunAnalysis([string] $Repo, [PSCustomObject] $Branch, [PSCustomObject] $RunData) {
    $headAnalysis = Get-BranchHeadRunAnalysis -Runs $RunData.Runs -Branch $Branch -IsComplete $RunData.IsComplete
    [PSCustomObject]@{
        Endpoint          = $RunData.Endpoint
        Runs              = $RunData.Runs
        Status            = $headAnalysis.Status
        MatchingRuns      = $headAnalysis.MatchingRuns
        LatestPerWorkflow = $headAnalysis.LatestPerWorkflow
        FailingRuns       = $headAnalysis.FailingRuns
        UnresolvedRuns    = $headAnalysis.UnresolvedRuns
        IsComplete        = $headAnalysis.IsComplete
        Repo              = $Repo
        BranchName        = $Branch.name
        BranchHeadSha     = $Branch.sha
    }
}

function Get-RenovateRunAnalysis([string] $Repo, [PSCustomObject] $Branch) {
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $runData = Get-RenovateRunData -Repo $Repo -Branch $Branch
            $analysis = New-RenovateRunAnalysis -Repo $Repo -Branch $Branch -RunData $runData
            if (($analysis.Status -ne 'Unknown' -and $analysis.IsComplete) -or $attempt -eq 2) { return $analysis }
        } catch {
            if ($attempt -eq 2) { throw }
        }

        Start-Sleep -Seconds 1
    }

    throw "Unable to determine run status for ${Repo}:$($Branch.name) after retry."
}

function ConvertTo-RunDiagnosticRows([object[]] $Runs) {
    foreach ($run in $Runs) {
        [PSCustomObject]@{
            WorkflowId = $run.workflow_id
            Workflow   = $run.name
            RunId      = $run.id
            HeadBranch = $run.head_branch
            HeadSha    = $run.head_sha
            CreatedAt  = $run.created_at
            Event      = $run.event
            Conclusion = $run.conclusion
        }
    }
}

function ConvertTo-MarkdownCell([object] $Value) {
    ([string]$Value -replace '\|', '\|') -replace "`r?`n", ' '
}

function Write-DiagnosticMarkdownRows([object[]] $Rows, [string] $SummaryFile) {
    '| Workflow ID | Workflow | Run ID | Head branch | Head SHA | Created | Event | Conclusion |' |
        Out-File -Append $SummaryFile
    '| --- | --- | --- | --- | --- | --- | --- | --- |' | Out-File -Append $SummaryFile
    foreach ($row in $Rows) {
        "| $(ConvertTo-MarkdownCell $row.WorkflowId) | $(ConvertTo-MarkdownCell $row.Workflow) | $(ConvertTo-MarkdownCell $row.RunId) | $(ConvertTo-MarkdownCell $row.HeadBranch) | $(ConvertTo-MarkdownCell $row.HeadSha) | $(ConvertTo-MarkdownCell $row.CreatedAt) | $(ConvertTo-MarkdownCell $row.Event) | $(ConvertTo-MarkdownCell $row.Conclusion) |" |
            Out-File -Append $SummaryFile
    }
    '' | Out-File -Append $SummaryFile
}

function Write-DiagnosticTable([string] $Title, [object[]] $Rows, [string] $SummaryFile) {
    if ($Rows.Count -eq 0) {
        "${Title}: no matching runs." | Out-File -Append $SummaryFile
        return
    }

    Write-Host $Title
    Write-Host ($Rows | Format-Table -AutoSize | Out-String -Width 500)
    $Title | Out-File -Append $SummaryFile
    Write-DiagnosticMarkdownRows $Rows $SummaryFile
}

function Write-DiagnosticMetadata([string[]] $Metadata, [string] $SummaryFile) {
    $codeSpan = '`'
    Write-Host 'Watchdog diagnostics:'
    $Metadata | ForEach-Object { Write-Host $_ }
    '## Watchdog diagnostics' | Out-File -Append $SummaryFile
    '| Field | Value |' | Out-File -Append $SummaryFile
    '| --- | --- |' | Out-File -Append $SummaryFile
    foreach ($entry in $Metadata) {
        $name, $value = $entry -split ': ', 2
        "| $name | $codeSpan$value$codeSpan |" | Out-File -Append $SummaryFile
    }
    '' | Out-File -Append $SummaryFile
}

function Write-WatchdogDiagnostics(
    [PSCustomObject] $Analysis,
    [string] $StateKey,
    [string] $PreviousStateValue,
    [string] $NewStateValue,
    [string] $SummaryFile
) {
    $metadata = @(
        "Repository: $($Analysis.Repo)"
        "Branch: $($Analysis.BranchName)"
        "Branch head SHA: $($Analysis.BranchHeadSha)"
        "Endpoint: $($Analysis.Endpoint)"
        "Returned runs: $($Analysis.Runs.Count)"
        "State ($StateKey): $PreviousStateValue -> $NewStateValue"
        "Current-head runs: $($Analysis.MatchingRuns.Count)"
        "Unresolved workflows: $($Analysis.UnresolvedRuns.Count)"
        "Complete response: $($Analysis.IsComplete)"
        "Status: $($Analysis.Status)"
    )

    Write-DiagnosticMetadata $metadata $SummaryFile
    Write-DiagnosticTable -Title 'Latest run per workflow' -Rows @(ConvertTo-RunDiagnosticRows $Analysis.LatestPerWorkflow) -SummaryFile $SummaryFile
}

function Copy-BranchState([hashtable] $Source, [hashtable] $Destination, [string] $BranchKey) {
    $prefix = "$BranchKey#"
    foreach ($key in $Source.Keys) {
        if ($key -eq $BranchKey -or $key.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
            $Destination[$key] = $Source[$key]
        }
    }
}

function Copy-BranchHeadState([hashtable] $Source, [hashtable] $Destination, [string] $BranchKey, [string] $HeadSha) {
    $prefix = "$BranchKey#$HeadSha#"
    foreach ($key in $Source.Keys) {
        if ($key.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
            $Destination[$key] = $Source[$key]
        }
    }
}

function Copy-RepositoryState([hashtable] $Source, [hashtable] $Destination, [string] $Repo) {
    $prefix = "$Repo#"
    foreach ($key in $Source.Keys) {
        if ($key.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
            $Destination[$key] = $Source[$key]
        }
    }
}

# --- Main ---
$previousState = Get-PreviousState $StateFilePath
$newState = @{}
$newFailures = [System.Collections.Generic.List[object]]::new()
$checkErrors = [System.Collections.Generic.List[string]]::new()
$unknownBranches = [System.Collections.Generic.List[object]]::new()
$excludedBranches = [System.Collections.Generic.List[object]]::new()

$activeBranchMap = Get-RenovateActiveBranchMap
if ($activeBranchMap.Available) {
    Write-Host "Loaded active-branch export from renovate.yml run $($activeBranchMap.RunId) (generated $($activeBranchMap.GeneratedAt))."
    "## ℹ️ Active-branch filtering: using renovate.yml run [$($activeBranchMap.RunId)](https://github.com/mu88/common/actions/runs/$($activeBranchMap.RunId)) (generated $($activeBranchMap.GeneratedAt))" |
        Out-File -Append $SummaryFile
} else {
    Write-Host "::warning::Active-branch export unavailable, checking all renovate/* branches for every repo. Reason: $($activeBranchMap.Reason)"
    "## ⚠️ Active-branch filtering unavailable: $($activeBranchMap.Reason)" | Out-File -Append $SummaryFile
}
'' | Out-File -Append $SummaryFile

$repos = @(Get-InstalledRepositories)
Write-Host "Discovered $($repos.Count) installed repositories."

foreach ($repo in $repos) {
    try {
        $branches = @(Get-RenovateBranches $repo)
    } catch {
        $message = "Failed to list branches for ${repo}: $_"
        Write-Host "::error::$message"
        $checkErrors.Add($message)
        Copy-RepositoryState -Source $previousState -Destination $newState -Repo $repo
        continue
    }

    if ($branches.Count -gt 0) {
        Write-Host "${repo}: found renovate branch(es) $($branches.name -join ', ')"
    }

    foreach ($branch in $branches) {
        $branchName = $branch.name
        $key = "$repo#$branchName"

        if ($activeBranchMap.Available -and $activeBranchMap.Repositories.ContainsKey($repo) -and
            $branchName -notin $activeBranchMap.Repositories[$repo]) {
            Write-Host "${repo}:${branchName}: skipping - not in Renovate's active-branch export (run $($activeBranchMap.RunId)), likely stale/orphaned"
            $excludedBranches.Add([PSCustomObject]@{ Repo = $repo; Branch = $branchName })
            # Preserve any previously-recorded failure state for this still-existing branch
            # so it isn't misreported as "new" once it becomes actively tracked again.
            Copy-BranchState -Source $previousState -Destination $newState -BranchKey $key
            continue
        }

        try {
            $analysis = Get-RenovateRunAnalysis $repo $branch
        } catch {
            $message = "Could not determine CI status for ${repo}:${branchName}; preserving its previous state. $_"
            Write-Host "::warning::$message"
            $unknownBranches.Add([PSCustomObject]@{ Repo = $repo; Branch = $branchName; Reason = [string]$_ })
            Copy-BranchState -Source $previousState -Destination $newState -BranchKey $key
            continue
        }

        if ($analysis.Status -eq 'Unknown') {
            $reason = if ($analysis.MatchingRuns.Count -eq 0) {
                'No completed run matched the current branch head.'
            } elseif (-not $analysis.IsComplete) {
                'The GitHub API response exceeded the response limit.'
            } else {
                'At least one current-head workflow has an inconclusive conclusion.'
            }
            $message = "${repo}:${branchName}: CI status is unknown after retry. $reason"
            Write-Host "::warning::$message"
            $unknownBranches.Add([PSCustomObject]@{ Repo = $repo; Branch = $branchName; Reason = $reason })
            Write-WatchdogDiagnostics $analysis $key $previousState[$key] $previousState[$key] $SummaryFile
            Write-DiagnosticTable -Title 'Runs returned by GitHub' -Rows @(ConvertTo-RunDiagnosticRows $analysis.Runs) -SummaryFile $SummaryFile
            Copy-BranchState -Source $previousState -Destination $newState -BranchKey $key
            continue
        }

        if ($analysis.Status -eq 'Success') {
            Write-Host "${repo}:${branchName}: current-head runs completed without failures"
            continue
        }

        foreach ($failingRun in $analysis.FailingRuns) {
            $stateKey = "$key#$($branch.sha)#$($failingRun.workflow_id)"
            $newState[$stateKey] = [string]$failingRun.id
            $previousRunId = $previousState[$stateKey]
            if (-not $previousRunId -and $previousState[$key] -eq [string]$failingRun.id) {
                $previousRunId = $previousState[$key]
            }
            Write-WatchdogDiagnostics $analysis $stateKey $previousRunId $newState[$stateKey] $SummaryFile
            if ($previousRunId -ne [string]$failingRun.id) {
                $newFailures.Add([PSCustomObject]@{
                    Repo       = $repo
                    Branch     = $branchName
                    Workflow   = $failingRun.name
                    Url        = $failingRun.html_url
                })
            }
        }

        foreach ($unresolvedRun in $analysis.UnresolvedRuns) {
            $stateKey = "$key#$($branch.sha)#$($unresolvedRun.workflow_id)"
            if ($previousState.ContainsKey($stateKey)) { $newState[$stateKey] = $previousState[$stateKey] }
        }
        if (-not $analysis.IsComplete) {
            $message = "${repo}:${branchName}: CI status is incomplete; preserving current-head failure state."
            Write-Host "::warning::$message"
            $unknownBranches.Add([PSCustomObject]@{ Repo = $repo; Branch = $branchName; Reason = 'The GitHub API result exceeded the response limit.' })
            Copy-BranchHeadState -Source $previousState -Destination $newState -BranchKey $key -HeadSha $branch.sha
        }
    }
}

# $newState contains keys for branches observed this run plus carried-forward state for
# branches excluded via the active-branch filter above; entries for branches that are
# genuinely gone (deleted/merged, no longer in the live branches listing at all) are
# pruned automatically since neither path ever adds a key for them.
$newState | ConvertTo-Json | Out-File $StateFilePath -Encoding utf8

if ($checkErrors.Count -gt 0) {
    '## ⚠️ Errors while checking repositories' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    foreach ($checkError in $checkErrors) { "- $checkError" | Out-File -Append $SummaryFile }
    '' | Out-File -Append $SummaryFile
}

if ($excludedBranches.Count -gt 0) {
    '## ℹ️ Branches excluded from checking (not in Renovate active-branch export)' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    '| Repo | Branch |' | Out-File -Append $SummaryFile
    '| --- | --- |' | Out-File -Append $SummaryFile
    foreach ($excluded in $excludedBranches) {
        "| [``$($excluded.Repo)``](https://github.com/$($excluded.Repo)) | ``$($excluded.Branch)`` |" | Out-File -Append $SummaryFile
    }
    '' | Out-File -Append $SummaryFile
}

if ($unknownBranches.Count -gt 0) {
    '## ⚠️ Renovate CI status could not be determined' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    '| Repo | Branch | Reason |' | Out-File -Append $SummaryFile
    '| --- | --- | --- |' | Out-File -Append $SummaryFile
    foreach ($unknown in $unknownBranches) {
        "| [``$($unknown.Repo)``](https://github.com/$($unknown.Repo)) | ``$($unknown.Branch)`` | $(ConvertTo-MarkdownCell $unknown.Reason) |" |
            Out-File -Append $SummaryFile
    }
    '' | Out-File -Append $SummaryFile
}

if ($newFailures.Count -gt 0) {
    '## 🔴 New Renovate CI failures detected' | Out-File -Append $SummaryFile
    '' | Out-File -Append $SummaryFile
    '| Repo | Branch | Workflow | Run |' | Out-File -Append $SummaryFile
    '| --- | --- | --- | --- |' | Out-File -Append $SummaryFile
    foreach ($failure in $newFailures) {
        "| [``$($failure.Repo)``](https://github.com/$($failure.Repo)) | ``$($failure.Branch)`` | $(ConvertTo-MarkdownCell $failure.Workflow) | [Run]($($failure.Url)) |" |
            Out-File -Append $SummaryFile
    }
}

if ($checkErrors.Count -gt 0 -or $newFailures.Count -gt 0) { exit 1 }

if ($unknownBranches.Count -eq 0) {
    '## ✅ No new Renovate CI failures' | Out-File -Append $SummaryFile
}
