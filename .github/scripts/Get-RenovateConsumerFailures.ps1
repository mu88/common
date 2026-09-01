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
