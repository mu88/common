param(
    [Parameter(Mandatory)] [string] $LogFile,
    [string] $SummaryFile = $env:GITHUB_STEP_SUMMARY,
    # Optional: if set, writes a machine-readable JSON export of the branches Renovate
    # currently actively tracks per repository, for consumption by other workflows
    # (e.g. the Renovate Consumer Watchdog, which needs to distinguish actively-tracked
    # `renovate/*` branches from stale/orphaned ones).
    [string] $ActiveBranchesFile
)

$ErrorActionPreference = 'Stop'

function Read-RenovateLog([string] $Path) {
    Get-Content $Path |
        Where-Object { $_ -match '^\{' } |
        ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
        Where-Object { $_ -ne $null }
}

function Format-RepoLink([string] $Name) {
    if ($Name -eq '(global)') { return '(global)' }
    "[``$Name``](https://github.com/$Name)"
}

function Get-ProcessingBranchNames([string] $Msg) {
    # Renovate logs exactly one such line per repository, e.g.:
    #   "Processing 0 branches: "
    #   "Processing 1 branch: renovate/all"
    #   "Processing 2 branches: renovate/all, renovate/all-dotnet"
    # This is Renovate's own authoritative list of branches it currently considers
    # relevant for that repo, independent of whether anything happened to them.
    if ($Msg -notmatch '^Processing \d+ branche?s?: ?(.*)$') { return $null }
    $namesPart = $matches[1].Trim()
    # The leading comma must sit directly on the array literal being returned: an
    # intermediate `$var = @(...)` assignment already unrolls a 0-element array to
    # $null and a 1-element array to a bare scalar, before any later comma could help.
    if ([string]::IsNullOrWhiteSpace($namesPart)) { return ,@() }
    return ,@($namesPart -split ',\s*')
}

function Get-RepoBranchMap([object[]] $Entries) {
    # Only trust a repo's branch list once it has fully finished processing
    # (result=done). A repo that errored out or never finished could have an
    # incomplete/partial "Processing N branches" snapshot, and treating that as
    # ground truth risks suppressing real watchdog alerts for branches Renovate
    # still cares about. This is intentionally stricter than Get-OverviewSection's
    # branch column above, which is purely informational for humans.
    $finishedRepos = $Entries |
        Where-Object { $_.msg -eq 'Repository finished' -and $_.result -eq 'done' -and $_.repository } |
        Select-Object -ExpandProperty repository -Unique

    $map = [ordered]@{}
    foreach ($repo in $finishedRepos) {
        $processingEntry = $Entries |
            Where-Object { $_.repository -eq $repo } |
            ForEach-Object { [PSCustomObject]@{ Branches = Get-ProcessingBranchNames $_.msg } } |
            Where-Object { $null -ne $_.Branches } |
            Select-Object -Last 1

        if ($null -eq $processingEntry) { continue } # no "Processing" line found - can't trust, omit repo
        $map[$repo] = $processingEntry.Branches
    }
    $map
}

function Export-ActiveBranches([System.Collections.Specialized.OrderedDictionary] $Map, [string] $Path) {
    $payload = [ordered]@{
        schemaVersion  = 1
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        runId          = $env:GITHUB_RUN_ID
        repositories   = $Map
    }
    $payload | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding utf8
}

function Get-OverviewSection([object[]] $Entries) {
    $repoFinished  = $Entries | Where-Object { $_.msg -eq 'Repository finished' }
    $updateEntries = $Entries | Where-Object { $_.msg -like '* flattened updates found*' }
    $branchEntries = $Entries | Where-Object { $_.branch -and $_.repository }

    $sortedRepos = $Entries |
        Where-Object { $_.repository } |
        Select-Object -ExpandProperty repository |
        Sort-Object -Unique |
        Sort-Object {
            $finished = $repoFinished | Where-Object { $_.repository -eq $_ } | Select-Object -Last 1
            if ($finished -and $finished.result -eq 'done') { 1 } else { 0 }
        }

    $lines = @(
        '## Renovate Run Overview'
        ''
        '| Repo | Updates | Branches | Result | Duration |'
        '| --- | --- | --- | --- | --- |'
    )

    foreach ($repo in $sortedRepos) {
        $finished     = $repoFinished | Where-Object { $_.repository -eq $repo } | Select-Object -Last 1
        $updatesEntry = $updateEntries | Where-Object { $_.repository -eq $repo } | Select-Object -Last 1
        $updatesCount = if ($updatesEntry -and $updatesEntry.msg -match '^(\d+) flattened') { $matches[1] } else { '—' }

        $branchStr = $branchEntries |
            Where-Object { $_.repository -eq $repo } |
            Select-Object -ExpandProperty branch |
            Sort-Object -Unique |
            ForEach-Object { "``$_``" }
        $branchStr = if ($branchStr) { $branchStr -join ', ' } else { '—' }

        $result   = if ($finished.result)     { $finished.result }                                    else { 'unknown' }
        $duration = if ($finished.durationMs) { "$([math]::Round($finished.durationMs / 1000, 1))s" } else { '—' }
        $icon     = if ($result -eq 'done')   { '✅' }                                else { '🔴' }

        $lines += "| $(Format-RepoLink $repo) | $updatesCount | $branchStr | $icon $result | $duration |"
    }

    $lines + ''
}

function Get-PendingSection([object[]] $Entries) {
    $pendingEntries = $Entries | Where-Object { $_.check -eq 'minimumReleaseAge' -and $_.level -lt 50 }
    if (-not $pendingEntries) { return }

    $lines = @(
        '## ⏳ Pending Updates (minimumReleaseAge)'
        ''
        '| Repo | Dependency | Pending versions |'
        '| --- | --- | --- |'
    )

    foreach ($entry in $pendingEntries) {
        $repo     = if ($entry.repository) { Format-RepoLink $entry.repository } else { '—' }
        $dep      = if ($entry.depName)    { "``$($entry.depName)``" }            else { '—' }
        $versions = if ($entry.versions)   { ($entry.versions | ForEach-Object { "``$_``" }) -join ', ' } else { '—' }
        $lines += "| $repo | $dep | $versions |"
    }

    $lines + ''
}

function Get-AutomergeSection([object[]] $Entries) {
    $allowedMessages  = @('automergedBranch', 'Branch automerge not possible', 'Skipping branch automerge',
                          'Branch automerged', 'Automerging branch')
    $automergeEntries = $Entries | Where-Object { $_.branch -and $_.msg -in $allowedMessages }
    if (-not $automergeEntries) { return }

    $lines = @(
        '## 🔀 Automerge Activity'
        ''
        '| Repo | Branch | Outcome |'
        '| --- | --- | --- |'
    )

    foreach ($entry in $automergeEntries) {
        $repo   = if ($entry.repository) { Format-RepoLink $entry.repository } else { '—' }
        $lines += "| $repo | ``$($entry.branch)`` | $($entry.msg -replace '\|', '\|') |"
    }

    $lines + ''
}

function Get-SkippedSection([object[]] $Entries) {
    $allowedMessages = @('Skipping branch', 'Branch is disabled', 'Update type not enabled',
                         'Skipping due to automerge lock', 'Scheduled update not required')
    $skippedEntries  = $Entries | Where-Object { $_.branch -and $_.msg -in $allowedMessages }
    if (-not $skippedEntries) { return }

    $lines = @(
        '## 🚫 Skipped / Blocked'
        ''
        '| Repo | Branch | Reason |'
        '| --- | --- | --- |'
    )

    foreach ($entry in $skippedEntries) {
        $repo   = if ($entry.repository) { Format-RepoLink $entry.repository } else { '—' }
        $lines += "| $repo | ``$($entry.branch)`` | $($entry.msg -replace '\|', '\|') |"
    }

    $lines + ''
}

function Format-CodeSpan([string] $Text) {
    $escaped = $Text -replace '\|', '\|'
    if ($escaped -notmatch '`') { return ('`' + $escaped + '`') }
    return ('`` ' + $escaped + ' ``')
}

function Get-IssuesSection([object[]] $Entries) {
    $issueEntries = $Entries | Where-Object { $_.level -ge 40 -and ($_.check -ne 'minimumReleaseAge' -or $_.level -ge 50) }

    if (-not $issueEntries) {
        return [PSCustomObject]@{ Lines = @('## ✅ No warnings or errors'); HasErrors = $false }
    }

    $levelLabel = @{ 40 = 'WARN'; 50 = 'ERROR'; 60 = 'FATAL' }
    $hasErrors  = $false
    $lines      = @('## 📢 Warnings and errors', '')

    $groups = $issueEntries | Group-Object { if ($_.repository) { $_.repository } else { '(global)' } }
    foreach ($group in $groups) {
        $lines += "### $(Format-RepoLink $group.Name)"
        $lines += ''
        $lines += '| Type | Message | Details |'
        $lines += '| --- | --- | --- |'

        foreach ($issue in $group.Group) {
            $level = [int]$issue.level
            if ($level -ge 50) { $hasErrors = $true }
            $icon  = if ($level -ge 50) { '❌' } else { '⚠️' }
            $label = if ($levelLabel.ContainsKey($level)) { $levelLabel[$level] } else { 'WARN' }

            $detailParts = [System.Collections.Generic.List[string]]::new()
            if ($issue.depName)  { $detailParts.Add("``$($issue.depName)``") }
            if ($issue.versions) { ($issue.versions | ForEach-Object { "``$_``" }) -join ', ' | ForEach-Object { $detailParts.Add($_) } }
            if ($issue.check)    { $detailParts.Add("check: ``$($issue.check)``") }
            $details = if ($detailParts.Count -gt 0) { $detailParts -join ' · ' } else { '' }

            $lines += "| $icon $label | $(Format-CodeSpan $issue.msg) | $details |"
        }
        $lines += ''
    }

    [PSCustomObject]@{ Lines = $lines; HasErrors = $hasErrors }
}

# --- Main ---
if (-not (Test-Path $LogFile)) {
    "## ❓ Renovate did not produce output (run may have failed before docker step)" |
        Out-File -Append $SummaryFile
    exit 0
}

$entries = Read-RenovateLog $LogFile

# Written before the HasErrors-driven exit below, so the export exists on disk
# regardless of whether this run is ultimately marked failed for unrelated reasons.
if ($ActiveBranchesFile) {
    Export-ActiveBranches (Get-RepoBranchMap $entries) $ActiveBranchesFile
}

$issues  = Get-IssuesSection $entries

@(
    Get-OverviewSection  $entries
    Get-PendingSection   $entries
    Get-AutomergeSection $entries
    Get-SkippedSection   $entries
    $issues.Lines
) | Out-File -Append $SummaryFile

if ($issues.HasErrors) { exit 1 }

