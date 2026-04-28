param(
    [Parameter(Mandatory)] [string] $LogFile,
    [string] $SummaryFile = $env:GITHUB_STEP_SUMMARY
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
$issues  = Get-IssuesSection $entries

@(
    Get-OverviewSection  $entries
    Get-PendingSection   $entries
    Get-AutomergeSection $entries
    Get-SkippedSection   $entries
    $issues.Lines
) | Out-File -Append $SummaryFile

if ($issues.HasErrors) { exit 1 }

