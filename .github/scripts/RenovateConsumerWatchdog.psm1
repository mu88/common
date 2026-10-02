function Test-RunMatchesBranchHead {
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Run,
        [Parameter(Mandatory)] [PSCustomObject] $Branch
    )

    if ([string]::Equals([string]$Run.head_sha, [string]$Branch.sha, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    if ($Run.event -ne 'pull_request' -or -not $Run.pull_requests) {
        return $false
    }

    foreach ($pullRequest in $Run.pull_requests) {
        if ($pullRequest.head.ref -eq $Branch.name -and
            [string]::Equals([string]$pullRequest.head.sha, [string]$Branch.sha, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-LatestRunsPerWorkflow {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Runs)

    $Runs |
        Sort-Object -Property @{ Expression = 'created_at'; Descending = $true }, @{ Expression = { [int]$_.run_attempt }; Descending = $true } |
        Group-Object -Property workflow_id |
        ForEach-Object { $_.Group[0] }
}

function Get-BranchHeadRunAnalysis {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Runs,
        [Parameter(Mandatory)] [PSCustomObject] $Branch,
        [bool] $IsComplete = $true
    )

    $matchingRuns = @($Runs | Where-Object { Test-RunMatchesBranchHead -Run $_ -Branch $Branch })
    $latestPerWorkflow = @(Get-LatestRunsPerWorkflow -Runs $matchingRuns)
    $failingRuns = @($latestPerWorkflow | Where-Object { $_.conclusion -eq 'failure' })
    $unresolvedRuns = @($latestPerWorkflow | Where-Object { $_.conclusion -notin @('success', 'failure') })
    $status = if ($failingRuns.Count -gt 0) {
        'Failure'
    } elseif (-not $IsComplete -or $matchingRuns.Count -eq 0 -or $unresolvedRuns.Count -gt 0) {
        'Unknown'
    } else {
        'Success'
    }

    [PSCustomObject]@{
        Status            = $status
        MatchingRuns      = $matchingRuns
        LatestPerWorkflow = $latestPerWorkflow
        FailingRuns       = $failingRuns
        UnresolvedRuns    = $unresolvedRuns
        IsComplete        = $IsComplete
    }
}

Export-ModuleMember -Function Get-BranchHeadRunAnalysis
