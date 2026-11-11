Describe 'Check-TemporaryPackagePins' {
BeforeAll {
    $script:guardScriptPath = Join-Path $PSScriptRoot '..\Check-TemporaryPackagePins.ps1'
    $script:driverPath = Join-Path $TestDrive 'Run-TemporaryPackagePinGuard.ps1'
    $driver = @'
$script:restoreCount = 0
$script:auditCount = 0

function dotnet {
    if ($args[0] -eq '--version') {
        $global:LASTEXITCODE = [int]$env:PIN_TEST_SDK_EXIT
        Write-Output $env:PIN_TEST_SDK_VERSION
        return
    }

    if ($args[0] -eq 'restore') {
        $script:restoreCount++
        Add-Content -LiteralPath $env:PIN_TEST_COMMAND_LOG -Value ($args -join ' ')
        if ($script:restoreCount -eq 1) {
            $global:LASTEXITCODE = [int]$env:PIN_TEST_RESTORE_EXIT_FIRST
            Write-Output $env:PIN_TEST_RESTORE_OUTPUT_FIRST
            return
        }

        $global:LASTEXITCODE = [int]$env:PIN_TEST_RESTORE_EXIT_SECOND
        Write-Output $env:PIN_TEST_RESTORE_OUTPUT_SECOND
        return
    }

    if ($args[0] -eq 'list') {
        $script:auditCount++
        Add-Content -LiteralPath $env:PIN_TEST_COMMAND_LOG -Value ($args -join ' ')
        if ($script:auditCount -eq 1) {
            $global:LASTEXITCODE = [int]$env:PIN_TEST_AUDIT_EXIT_FIRST
            Write-Output $env:PIN_TEST_BASELINE_JSON
            return
        }

        $global:LASTEXITCODE = [int]$env:PIN_TEST_AUDIT_EXIT_SECOND
        Write-Output $env:PIN_TEST_CANDIDATE_JSON
        return
    }

    $global:LASTEXITCODE = 90
}

& $env:PIN_TEST_GUARD_SCRIPT -WorkspaceRoot $env:PIN_TEST_WORKSPACE_ROOT -SolutionPath 'Probe.sln'
if (-not $?) {
    exit 1
}
'@
    Set-Content -LiteralPath $script:driverPath -Value $driver -Encoding utf8NoBOM

    function New-VulnerabilityReport {
        param(
            [Parameter(Mandatory)]
            [string]$Framework,

            [Parameter(Mandatory)]
            [string]$PackageId,

            [Parameter(Mandatory)]
            [string]$ResolvedVersion,

            [Parameter(Mandatory)]
            [string]$AdvisoryUrl,

            [string]$PackageType = 'topLevelPackages'
        )

        $package = @{
            id = $PackageId
            resolvedVersion = $ResolvedVersion
            vulnerabilities = @(@{ severity = 'Moderate'; advisoryurl = $AdvisoryUrl })
        }
        $frameworkReport = @{ framework = $Framework }
        $frameworkReport[$PackageType] = @($package)

        return @{
            version = 1
            parameters = '--vulnerable --include-transitive'
            sources = @()
            projects = @(@{ path = 'Probe.csproj'; frameworks = @($frameworkReport) })
        } | ConvertTo-Json -Depth 10 -Compress
    }

    function Invoke-PinGuard {
        $env:PIN_TEST_BASELINE_JSON = $script:baselineReport
        $env:PIN_TEST_CANDIDATE_JSON = $script:candidateReport

        $output = & pwsh -NoLogo -NoProfile -File $script:driverPath 2>&1 | Out-String

        return [PSCustomObject]@{
            ExitCode = $LASTEXITCODE
            Output = $output
            Commands = Get-Content -LiteralPath $script:commandLog -Raw
        }
    }
}

BeforeEach {
    $script:workspaceRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:workspaceRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Directory.Packages.props') -Value @'
<Project>
  <ItemGroup>
    <!-- TEMP-PIN: GHSA-6527-9fp8-r4x6 -->
    <PackageVersion Include="Microsoft.AspNetCore.WebUtilities" Version="2.3.14" />
  </ItemGroup>
</Project>
'@ -Encoding utf8NoBOM
    Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Probe.sln') -Value 'Fake solution for the dotnet test shim.' -Encoding utf8NoBOM

    $script:stateDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:stateDirectory -Force | Out-Null
    $script:commandLog = Join-Path $script:stateDirectory 'commands.txt'
    Set-Content -LiteralPath $script:commandLog -Value '' -NoNewline

    $script:cleanReport = @{
        version = 1
        parameters = '--vulnerable --include-transitive'
        sources = @()
        projects = @(@{ path = 'Probe.csproj' })
    } | ConvertTo-Json -Depth 10 -Compress

    $script:baselineReport = $script:cleanReport
    $script:candidateReport = $script:cleanReport
    $script:previousRestoreLockedMode = $env:RestoreLockedMode
    $env:PIN_TEST_GUARD_SCRIPT = $script:guardScriptPath
    $env:PIN_TEST_WORKSPACE_ROOT = $script:workspaceRoot
    $env:PIN_TEST_SDK_VERSION = '10.0.403'
    $env:PIN_TEST_SDK_EXIT = '0'
    $env:PIN_TEST_RESTORE_EXIT_FIRST = '0'
    $env:PIN_TEST_RESTORE_EXIT_SECOND = '0'
    $env:PIN_TEST_RESTORE_OUTPUT_FIRST = ''
    $env:PIN_TEST_RESTORE_OUTPUT_SECOND = ''
    $env:PIN_TEST_AUDIT_EXIT_FIRST = '0'
    $env:PIN_TEST_AUDIT_EXIT_SECOND = '0'
    $env:PIN_TEST_COMMAND_LOG = $script:commandLog
}

AfterEach {
    @(
        'PIN_TEST_GUARD_SCRIPT',
        'PIN_TEST_WORKSPACE_ROOT',
        'PIN_TEST_SDK_VERSION',
        'PIN_TEST_SDK_EXIT',
        'PIN_TEST_RESTORE_EXIT_FIRST',
        'PIN_TEST_RESTORE_EXIT_SECOND',
        'PIN_TEST_RESTORE_OUTPUT_FIRST',
        'PIN_TEST_RESTORE_OUTPUT_SECOND',
        'PIN_TEST_AUDIT_EXIT_FIRST',
        'PIN_TEST_AUDIT_EXIT_SECOND',
        'PIN_TEST_BASELINE_JSON',
        'PIN_TEST_CANDIDATE_JSON',
        'PIN_TEST_COMMAND_LOG'
    ) | ForEach-Object { Remove-Item -Path "Env:$_" -ErrorAction SilentlyContinue }
    if ($null -eq $script:previousRestoreLockedMode) {
        Remove-Item -Path Env:RestoreLockedMode -ErrorAction SilentlyContinue
    }
    else {
        $env:RestoreLockedMode = $script:previousRestoreLockedMode
    }
}

    It 'detects a vulnerable package from JSON even when no NU1901-NU1904 text codes are emitted' {
        $script:candidateReport = New-VulnerabilityReport `
            -Framework 'net10.0' `
            -PackageId 'Microsoft.AspNetCore.WebUtilities' `
            -ResolvedVersion '2.3.0' `
            -AdvisoryUrl 'https://github.com/advisories/GHSA-6527-9fp8-r4x6' `
            -PackageType 'transitivePackages'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match "Temporary pin 'Microsoft.AspNetCore.WebUtilities' \(2.3.14\) is still needed\."
        $result.Output | Should -Not -Match 'can be removed'
        $result.Commands | Should -Match '--vulnerable --include-transitive --format json --output-version 1 --no-restore'
    }

    It 'handles multiple projects when unaffected projects omit the frameworks property' {
        $script:candidateReport = @{
            version = 1
            parameters = '--vulnerable --include-transitive'
            sources = @()
            projects = @(
                @{ path = 'Unaffected.csproj' },
                @{
                    path = 'Affected.csproj'
                    frameworks = @(@{
                        framework = 'net10.0'
                        transitivePackages = @(@{
                            id = 'Microsoft.AspNetCore.WebUtilities'
                            resolvedVersion = '2.3.0'
                            vulnerabilities = @(@{ severity = 'Moderate'; advisoryurl = 'https://github.com/advisories/GHSA-6527-9fp8-r4x6' })
                        })
                    })
                }
            )
        } | ConvertTo-Json -Depth 10 -Compress

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'is still needed'
    }

    It 'checks the baseline audit before treating a conditional direct PackageReference as indeterminate' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Probe.csproj') -Value @'
<Project>
  <ItemGroup Condition="'$(TargetFramework)' == 'net10.0'">
    <PackageReference Include="Microsoft.AspNetCore.WebUtilities" />
  </ItemGroup>
</Project>
'@ -Encoding utf8NoBOM

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'PackageReference.*Probe\.csproj'
        $result.Output | Should -Match 'conditional declaration'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
        @($result.Commands -split "`r?`n" | Where-Object { $_ -match '^restore ' }) | Should -HaveCount 1
        @($result.Commands -split "`r?`n" | Where-Object { $_ -match '^list ' }) | Should -HaveCount 1
    }

    It 'does not let a direct PackageReference hide a baseline audit error' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Probe.csproj') -Value '<Project><ItemGroup><PackageReference Include="Microsoft.AspNetCore.WebUtilities" /></ItemGroup></Project>' -Encoding utf8NoBOM
        $env:PIN_TEST_AUDIT_EXIT_FIRST = '1'
        $script:baselineReport = 'baseline audit failed'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Vulnerability audit failed'
        $result.Output | Should -Not -Match 'inconclusive|direct PackageReference'
    }

    It 'does not let a direct PackageReference hide a baseline restore failure' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Probe.csproj') -Value '<Project><ItemGroup><PackageReference Include="Microsoft.AspNetCore.WebUtilities" /></ItemGroup></Project>' -Encoding utf8NoBOM
        $env:PIN_TEST_RESTORE_EXIT_FIRST = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_FIRST = 'error NU1301: Unable to load the service index.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1301'
        $result.Output | Should -Not -Match 'inconclusive|direct PackageReference'
    }

    It 'detects exact PackageReference Update declarations in props files' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Directory.Build.props') -Value @'
<Project>
  <ItemGroup Condition="'$(Configuration)' == 'Release'">
    <PackageReference Update="Other.Package;Microsoft.AspNetCore.WebUtilities" />
  </ItemGroup>
</Project>
'@ -Encoding utf8NoBOM

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'PackageReference Update.*Directory\.Build\.props'
        $result.Output | Should -Match 'conditional declaration'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'detects direct PackageReference Include declarations in targets files' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Custom.targets') -Value @'
<Project>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.WebUtilities" />
  </ItemGroup>
</Project>
'@ -Encoding utf8NoBOM

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'PackageReference Include.*Custom\.targets'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'does not treat a PackageReference package-name substring as a direct reference' {
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Probe.csproj') -Value @'
<Project>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.WebUtilities.Extensions" />
  </ItemGroup>
</Project>
'@ -Encoding utf8NoBOM

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Remove temporary pin'
        $result.Output | Should -Not -Match 'inconclusive|direct PackageReference'
    }

    It 'allows removal when both vulnerability reports contain no findings' {
        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Remove temporary pin'
        $result.Output | Should -Match 'no new vulnerability findings'
        $result.Commands | Should -Match '--format json'
    }

    It 'does not attribute an unchanged vulnerability in another package to the temporary pin' {
        $unrelatedFinding = New-VulnerabilityReport `
            -Framework 'net8.0' `
            -PackageId 'Unrelated.Package' `
            -ResolvedVersion '1.0.0' `
            -AdvisoryUrl 'https://example.test/advisory/unrelated'
        $script:baselineReport = $unrelatedFinding
        $script:candidateReport = $unrelatedFinding

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Remove temporary pin'
        $result.Output | Should -Not -Match 'is still needed'
    }

    It 'detects a new vulnerability in a later target framework even when it belongs to another package' {
        $script:candidateReport = @{
            version = 1
            parameters = '--vulnerable --include-transitive'
            sources = @()
            projects = @(@{
                path = 'Probe.csproj'
                frameworks = @(
                    @{ framework = 'net10.0'; topLevelPackages = @() },
                    @{
                        framework = 'net8.0'
                        transitivePackages = @(@{
                            id = 'Unrelated.Package'
                            resolvedVersion = '1.0.0'
                            vulnerabilities = @(@{ severity = 'Moderate'; advisoryurl = 'https://example.test/advisory/new' })
                        })
                    }
                )
            })
        } | ConvertTo-Json -Depth 10 -Compress

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'is still needed'
    }

    It 'does not classify a direct-package NU1010 restore failure as proof that the pin is needed' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'NU1010'
        $result.Output | Should -Match 'inconclusive'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'treats NU1010 for a direct SQLite pin as indeterminate and continues successfully' {
        [xml]$packageDocument = Get-Content -LiteralPath (Join-Path $script:workspaceRoot 'Directory.Packages.props') -Raw
        $marker = @($packageDocument.SelectNodes("//*[local-name()='PackageVersion' and @Include='Microsoft.AspNetCore.WebUtilities']"))[0]
        $marker.SetAttribute('Include', 'SQLitePCLRaw.bundle_e_sqlite3')
        $marker.SetAttribute('Version', '3.0.5')
        Set-Content -LiteralPath (Join-Path $script:workspaceRoot 'Directory.Packages.props') -Value $packageDocument.OuterXml -Encoding utf8NoBOM
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: SQLitePCLRaw.bundle_e_sqlite3. Projects using Central Package Management must declare matching items.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'SQLitePCLRaw\.bundle_e_sqlite3'
        $result.Output | Should -Match 'inconclusive'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'keeps repeated NU1010 diagnostics for only the removed package indeterminate' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $matchingDiagnostic = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = "$matchingDiagnostic`n$matchingDiagnostic"

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'inconclusive'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'fails when a pure NU1010 restore failure has an unexpected exit code' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '2'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'restore failed'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'fails when matching NU1010 is accompanied by another package restore error' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = @'
error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.
error NU1101: Unable to find package Other.Package.
'@

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1101'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'fails when an NU1010 diagnostic also names a different package' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = @'
error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.
error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Other.Direct.Package. Projects using Central Package Management must declare matching items.
'@

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1010'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'does not match a package-name substring in an NU1010 diagnostic' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities.Extensions. Projects using Central Package Management must declare matching items.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1010'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'fails when a restore task error accompanies the matching NU1010 diagnostic' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = @'
error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items.
C:\Program Files\dotnet\sdk\NuGet.targets(198,5): error : Object reference not set to an instance of an object.
'@

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Object reference'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'fails on candidate restore errors other than the matching NU1010 package-version condition' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1301: Unable to load the service index.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1301'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'does not let matching NU1010 hide a restore vulnerability-audit error' {
        $env:PIN_TEST_RESTORE_EXIT_SECOND = '1'
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'error NU1010: The following PackageReference items do not define a corresponding PackageVersion item: Microsoft.AspNetCore.WebUtilities. Projects using Central Package Management must declare matching items. warning NU1900: Unable to retrieve vulnerability data.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1900'
        $result.Output | Should -Not -Match 'inconclusive|is still needed|can be removed'
    }

    It 'disables locked mode for scratch restores without changing the configured environment value' {
        $env:RestoreLockedMode = 'true'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Remove temporary pin'
        $restoreCommands = @($result.Commands -split "`r?`n" | Where-Object { $_ -match '^restore ' })
        $restoreCommands | Should -HaveCount 2
        foreach ($restoreCommand in $restoreCommands) {
            $restoreCommand | Should -Match '-p:RestoreLockedMode=false$'
        }
    }

    It 'fails when restore reports NU1900 despite a successful restore exit code' {
        $env:PIN_TEST_RESTORE_OUTPUT_SECOND = 'warning NU1900: Unable to retrieve vulnerability data.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1900'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'fails when the vulnerability audit exits unsuccessfully' {
        $env:PIN_TEST_AUDIT_EXIT_SECOND = '1'
        $script:candidateReport = 'audit failed'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Vulnerability audit failed'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'fails when NU1900 reports unavailable vulnerability data even if the command exits successfully' {
        $script:candidateReport = 'warning NU1900: Unable to retrieve vulnerability data.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'NU1900'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'fails closed for malformed JSON instead of treating absent text codes as a clean audit' {
        $script:candidateReport = 'No vulnerable packages found.'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'valid JSON'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }

    It 'rejects SDK versions that do not support vulnerability JSON output' {
        $env:PIN_TEST_SDK_VERSION = '9.0.299'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match '9\.0\.300'
        $result.Commands | Should -BeNullOrEmpty
    }

    It 'fails when the SDK version check exits unsuccessfully' {
        $env:PIN_TEST_SDK_EXIT = '1'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Could not determine the \.NET SDK version'
        $result.Commands | Should -BeNullOrEmpty
    }

    It 'accepts the minimum SDK version that supports vulnerability JSON output' {
        $env:PIN_TEST_SDK_VERSION = '9.0.300'

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Remove temporary pin'
        $result.Commands | Should -Match '--format json --output-version 1'
    }

    It 'rejects unsupported vulnerability JSON report versions' {
        $script:candidateReport = @{
            version = 2
            parameters = '--vulnerable --include-transitive'
            projects = @(@{ path = 'Probe.csproj' })
        } | ConvertTo-Json -Depth 10 -Compress

        $result = Invoke-PinGuard

        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'unsupported or incomplete JSON report'
        $result.Output | Should -Not -Match 'is still needed|can be removed'
    }
}
