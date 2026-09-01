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

function Get-GitHubRequestId([string[]] $Lines) {
    $requestId = $null
    foreach ($line in $Lines) {
        if ($line -match '^x-github-request-id:\s*(.+)$') {
            $requestId = $matches[1].Trim()
        }
    }
    $requestId
}

function Get-ResponseBodyStartIndex([string[]] $Lines) {
    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ([string]::IsNullOrWhiteSpace($Lines[$index])) {
            $bodyStartIndex = $index + 1
            if ($bodyStartIndex -lt $Lines.Count) { return $bodyStartIndex }
        }
    }

    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ($Lines[$index] -match '^\s*\[') { return $index }
    }

    -1
}

function Invoke-GhApiWithResponseMetadata([string[]] $Arguments) {
    $output = & gh @Arguments '--include' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh $($Arguments -join ' ') failed with exit code ${LASTEXITCODE}."
    }

    $lines = @($output | ForEach-Object { [string]$_ })
    $bodyStartIndex = Get-ResponseBodyStartIndex $lines
    if ($bodyStartIndex -lt 0) {
        throw 'gh API response did not contain a JSON body.'
    }

    [PSCustomObject]@{
        Body      = ($lines[$bodyStartIndex..($lines.Count - 1)] -join [Environment]::NewLine)
        RequestId = Get-GitHubRequestId $lines
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

function Get-LatestRunsPerWorkflow([object[]] $Runs) {
    $Runs |
        Sort-Object -Property created_at -Descending |
        Group-Object -Property workflow_id |
        ForEach-Object { $_.Group[0] }
}

function Get-RenovateRunAnalysis([string] $Repo, [PSCustomObject] $Branch) {
    # Look at more than the single latest run: a branch can trigger several
    # workflows (e.g. CI + a linter) on the same push, and only checking the
    # most recently created run could miss a failure in a sibling workflow.
    # No `event=` filter, so this also covers repos whose CI only triggers on
    # `pull_request` once Renovate opens a PR for the branch.
    $encodedBranch = [System.Uri]::EscapeDataString($Branch.name)
    $endpoint = "repos/$Repo/actions/runs?branch=$encodedBranch&status=completed&per_page=20"
    $response = Invoke-GhApiWithResponseMetadata @(
        'api', $endpoint,
        '--jq', '.workflow_runs'
    )
    $runs = @($response.Body | ConvertFrom-Json)

    $latestPerWorkflow = @(Get-LatestRunsPerWorkflow $runs)

    [PSCustomObject]@{
        Endpoint          = $endpoint
        EncodedBranch     = $encodedBranch
        RequestId         = $response.RequestId
        Runs              = $runs
        LatestPerWorkflow = @($latestPerWorkflow)
        FailingRun        = $latestPerWorkflow | Where-Object { $_.conclusion -eq 'failure' } | Select-Object -First 1
        Repo              = $Repo
        BranchName        = $Branch.name
        BranchHeadSha     = $Branch.sha
    }
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
        "${Title}: no runs returned." | Out-File -Append $SummaryFile
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
        "Encoded branch parameter: $($Analysis.EncodedBranch)"
        "Endpoint: $($Analysis.Endpoint)"
        "GitHub request ID: $($Analysis.RequestId)"
        "Returned runs: $($Analysis.Runs.Count)"
        "State ($StateKey): $PreviousStateValue -> $NewStateValue"
        "Failure candidate: $($Analysis.FailingRun.id)"
    )

    Write-DiagnosticMetadata $metadata $SummaryFile
    Write-DiagnosticTable -Title 'Queried completed runs' -Rows @(ConvertTo-RunDiagnosticRows $Analysis.Runs) -SummaryFile $SummaryFile
    Write-DiagnosticTable -Title 'Latest run per workflow' -Rows @(ConvertTo-RunDiagnosticRows $Analysis.LatestPerWorkflow) -SummaryFile $SummaryFile
}

# --- Main ---
$previousState = Get-PreviousState $StateFilePath
$newState = @{}
$newFailures = [System.Collections.Generic.List[object]]::new()
$checkErrors = [System.Collections.Generic.List[string]]::new()
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
            if ($previousState.ContainsKey($key)) { $newState[$key] = $previousState[$key] }
            continue
        }

        try {
            $analysis = Get-RenovateRunAnalysis $repo $branch
            $failingRun = $analysis.FailingRun
        } catch {
            $message = "Failed to check runs for ${repo}:${branchName}: $_"
            Write-Host "::error::$message"
            $checkErrors.Add($message)
            continue
        }

        if (-not $failingRun) {
            Write-Host "${repo}:${branchName}: no failing run found"
            continue
        }

        Write-Host "${repo}:${branchName}: latest failing run is $($failingRun.id) ($($failingRun.html_url))"
        $newState[$key] = [string]$failingRun.id
        Write-WatchdogDiagnostics $analysis $key $previousState[$key] $newState[$key] $SummaryFile
        if ($previousState[$key] -ne [string]$failingRun.id) {
            $newFailures.Add([PSCustomObject]@{ Repo = $repo; Branch = $branchName; Url = $failingRun.html_url })
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
