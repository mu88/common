Import-Module (Join-Path $PSScriptRoot '..\RenovateConsumerWatchdog.psm1') -Force

Describe 'Get-BranchHeadRunAnalysis' {
    BeforeAll {
        $branch = [PSCustomObject]@{
            name = 'renovate/example'
            sha  = 'current-head'
        }
    }

    It 'ignores failures from older branch heads when the current head succeeded' {
        $runs = @(
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'old-head'
                event       = 'push'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            },
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'success'
                created_at  = '2026-10-01T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Success'
        @($result.FailingRuns).Count | Should -Be 0
    }

    It 'returns Unknown when no run can be matched to the current branch head' {
        $runs = @(
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'old-head'
                event       = 'push'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Unknown'
        @($result.MatchingRuns).Count | Should -Be 0
    }

    It 'does not treat an inconclusive current-head run as success' {
        $runs = @(
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'cancelled'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Unknown'
        $result.UnresolvedRuns[0].conclusion | Should -Be 'cancelled'
    }

    It 'returns Unknown when the API response is incomplete, even if returned runs succeeded' {
        $runs = @(
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'success'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch -IsComplete $false

        $result.Status | Should -Be 'Unknown'
    }

    It 'keeps a confirmed head failure actionable when the API response is incomplete' {
        $runs = @(
            [PSCustomObject]@{
                id          = 789
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch -IsComplete $false

        $result.Status | Should -Be 'Failure'
        $result.FailingRuns[0].id | Should -Be 789
    }

    It 'detects a failure on the current branch head' {
        $runs = @(
            [PSCustomObject]@{
                id          = 123
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Failure'
        $result.FailingRuns[0].id | Should -Be 123
    }

    It 'matches pull-request runs through the pull-request head when the run SHA is a merge SHA' {
        $runs = @(
            [PSCustomObject]@{
                id          = 456
                workflow_id = 2
                head_sha    = 'merge-sha'
                event       = 'pull_request'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
                pull_requests = @(
                    [PSCustomObject]@{
                        head = [PSCustomObject]@{
                            ref = 'renovate/example'
                            sha = 'current-head'
                        }
                    }
                )
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Failure'
        $result.FailingRuns[0].id | Should -Be 456
    }

    It 'uses a successful rerun instead of an earlier failed attempt' {
        $runs = @(
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'failure'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 1
            },
            [PSCustomObject]@{
                workflow_id = 1
                head_sha    = 'current-head'
                event       = 'push'
                conclusion  = 'success'
                created_at  = '2026-10-02T10:00:00Z'
                run_attempt = 2
            }
        )

        $result = Get-BranchHeadRunAnalysis -Runs $runs -Branch $branch

        $result.Status | Should -Be 'Success'
        $result.LatestPerWorkflow[0].run_attempt | Should -Be 2
    }
}
