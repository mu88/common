Import-Module (Join-Path $PSScriptRoot '..\TemporaryPackagePinAudit.psm1') -Force

function Format-AuditReport {
    param(
        [Parameter(Mandatory = $true)] [string]$Projects,
        [int]$Version = 1,
        [string]$Parameters = '--vulnerable --include-transitive'
    )

    return '{"version":' + $Version + ',"parameters":"' + $Parameters + '","sources":["https://api.nuget.org/v3/index.json"],"projects":[' + $Projects + ']}'
}

$webUtilitiesVulnerability = '{"id":"Microsoft.AspNetCore.WebUtilities","resolvedVersion":"2.3.0","vulnerabilities":[{"severity":"Moderate","advisoryurl":"https://github.com/advisories/GHSA-6527-9fp8-r4x6"}]}'
$newtonsoftVulnerabilities = '{"id":"Newtonsoft.Json","resolvedVersion":"9.0.1","vulnerabilities":[{"severity":"High","advisoryurl":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr"},{"severity":"Low","advisoryurl":"https://example.invalid/advisory"}]}'
$cleanProject = '{"path":"Clean.csproj"}'
$directProject = '{"path":"Vuln.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[' + $webUtilitiesVulnerability + ']}]}'
$transitiveProject = '{"path":"Transitive.csproj","frameworks":[{"framework":"net10.0","transitivePackages":[' + $webUtilitiesVulnerability + ',{"id":"Newtonsoft.Json","resolvedVersion":"9.0.1","vulnerabilities":[{"severity":"High","advisoryurl":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr"}]}]}]}'
$multiProjects = '{"path":"A.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[' + $webUtilitiesVulnerability + ']},{"framework":"net10.0-windows","transitivePackages":[' + $newtonsoftVulnerabilities + ']}]},{"path":"B.csproj"}'

function New-ValidCase {
    param([string]$Name, [string]$Output, [int]$Expected)

    return @{ Name = $Name; Output = $Output; Expected = $Expected }
}

function New-InvalidCase {
    param([string]$Name, [string]$Output, [string]$StandardError = '', [int]$ExitCode = 0)

    return @{ Name = $Name; Output = $Output; StandardError = $StandardError; ExitCode = $ExitCode }
}

$validCases = @(
    New-ValidCase -Name 'a clean report without frameworks' -Output (Format-AuditReport -Projects $cleanProject) -Expected 0
    New-ValidCase -Name 'one direct vulnerable package without NU code' -Output (Format-AuditReport -Projects $directProject) -Expected 1
    New-ValidCase -Name 'transitive vulnerable packages without NU code' -Output (Format-AuditReport -Projects $transitiveProject) -Expected 2
    New-ValidCase -Name 'direct and transitive packages across projects and frameworks' -Output (Format-AuditReport -Projects $multiProjects) -Expected 3
)

$cleanOutput = Format-AuditReport -Projects $cleanProject

$invalidCases = @(
    New-InvalidCase -Name 'non-zero audit exit code' -Output $cleanOutput -ExitCode 1
    New-InvalidCase -Name 'NU1900 on stderr next to clean JSON' -Output $cleanOutput -StandardError 'warning NU1900: Error occurred while getting package vulnerability data'
    New-InvalidCase -Name 'NU1902 on stderr next to clean JSON' -Output $cleanOutput -StandardError "warning NU1902: Package 'Example' 1.0.0 has a moderate severity vulnerability"
    New-InvalidCase -Name 'NU1905 on stderr next to clean JSON' -Output $cleanOutput -StandardError "warning NU1905: Audit source 'empty' did not provide any vulnerability data."
    New-InvalidCase -Name 'NU1903 on stdout next to valid JSON' -Output ("warning NU1903: Package 'Example' 1.0.0 has a high severity vulnerability`n" + $cleanOutput)
    New-InvalidCase -Name 'empty output' -Output ''
    New-InvalidCase -Name 'non-JSON output' -Output 'The following sources were used: nuget.org'
    New-InvalidCase -Name 'unsupported report version' -Output (Format-AuditReport -Projects $cleanProject -Version 2)
    New-InvalidCase -Name 'report without projects' -Output '{"version":1,"parameters":"--vulnerable --include-transitive","projects":[]}'
    New-InvalidCase -Name 'project without path' -Output '{"version":1,"parameters":"--vulnerable --include-transitive","projects":[{"frameworks":[]}]}'
    New-InvalidCase -Name 'package without id' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[{"resolvedVersion":"2.3.0"}]}]}')
    New-InvalidCase -Name 'frameworks given as object' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":{"framework":"net10.0"}}')
    New-InvalidCase -Name 'frameworks explicitly null' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":null}')
    New-InvalidCase -Name 'transitivePackages explicitly null' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":[{"framework":"net10.0","transitivePackages":null}]}')
    New-InvalidCase -Name 'projects given as object' -Output '{"version":1,"parameters":"--vulnerable --include-transitive","projects":{"path":"App.csproj"}}'
    New-InvalidCase -Name 'parameters missing' -Output '{"version":1,"projects":[{"path":"App.csproj"}]}'
    New-InvalidCase -Name 'parameters without --include-transitive' -Output (Format-AuditReport -Projects $cleanProject -Parameters '--vulnerable')
    New-InvalidCase -Name 'transitive package without vulnerabilities' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":[{"framework":"net10.0","transitivePackages":[{"id":"Example"}]}]}')
    New-InvalidCase -Name 'package with empty vulnerabilities array' -Output (Format-AuditReport -Projects '{"path":"A.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[{"id":"Example","resolvedVersion":"1.0.0","vulnerabilities":[]}]}]}')
    New-InvalidCase -Name 'problem reported next to clean projects' -Output '{"version":1,"parameters":"--vulnerable --include-transitive","problems":[{"project":"App.csproj","level":"warning","text":"Audit source ''empty'' did not provide any vulnerability data."}],"projects":[{"path":"App.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[]}]}]}'
)

Describe 'Get-AuditVulnerabilityCount counts findings in real report shapes' {
    It 'returns <Expected> for <Name>' -ForEach $validCases {
        # Act
        $count = Get-AuditVulnerabilityCount -ExitCode 0 -StandardOutput $Output -StandardError ''

        # Assert
        $count | Should -Be $Expected
    }
}

Describe 'Get-AuditVulnerabilityCount fails closed on incomplete or unsupported output' {
    It 'throws for <Name>' -ForEach $invalidCases {
        # Act & Assert
        { Get-AuditVulnerabilityCount -ExitCode $ExitCode -StandardOutput $Output -StandardError $StandardError } | Should -Throw
    }
}

Describe 'Check-TemporaryPackagePins.ps1 with real dotnet' -Tag 'Integration' {
    $auditVariants = @(
        @{ Id = 'audit-on'; Name = 'NuGetAudit enabled'; ProjectProperties = '' }
        @{ Id = 'audit-off'; Name = 'NuGetAudit disabled'; ProjectProperties = '<NuGetAudit>false</NuGetAudit>' }
    )

    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\Check-TemporaryPackagePins.ps1'
        $workRoot = Join-Path ([IO.Path]::GetTempPath()) ("temp-pin-tests-" + [guid]::NewGuid().ToString('N'))
        $vulnerablePackageVersions = @'
    <PackageVersion Include="Microsoft.AspNetCore.Mvc.Core" Version="2.3.0" />
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
    <!-- TEMP-PIN: GHSA-6527-9fp8-r4x6 -->
    <PackageVersion Include="Microsoft.AspNetCore.WebUtilities" Version="2.3.14" />
'@
        $cleanPackageVersions = @'
    <PackageVersion Include="Microsoft.Extensions.Logging" Version="10.0.0" />
    <!-- TEMP-PIN: test -->
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.0" />
'@

        function New-Workspace {
            param(
                [Parameter(Mandatory = $true)] [string]$Name,
                [Parameter(Mandatory = $true)] [string]$PackageVersions,
                [Parameter(Mandatory = $true)] [string]$ProjectReferences,
                [string]$ProjectProperties = '',
                [string]$NuGetConfig = '',
                [switch]$TransitivePinning
            )

            $workspace = Join-Path $workRoot $Name
            $null = New-Item -ItemType Directory -Path $workspace -Force
            if ($NuGetConfig) {
                Set-Content -LiteralPath (Join-Path $workspace 'NuGet.Config') -Value $NuGetConfig
            }
            $transitivePinningProperty = if ($TransitivePinning) { '<CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>' } else { '' }
            Set-Content -LiteralPath (Join-Path $workspace 'Directory.Packages.props') -Value @"
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    $transitivePinningProperty
  </PropertyGroup>
  <ItemGroup>
$PackageVersions
  </ItemGroup>
</Project>
"@
            Set-Content -LiteralPath (Join-Path $workspace 'App.csproj') -Value @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    $ProjectProperties
  </PropertyGroup>
  <ItemGroup>
    $ProjectReferences
  </ItemGroup>
</Project>
"@

            return $workspace
        }

        function New-VulnerableWorkspace {
            param(
                [Parameter(Mandatory = $true)] [string]$Name,
                [string]$ProjectProperties = ''
            )

            return New-Workspace -Name $Name -PackageVersions $vulnerablePackageVersions `
                -ProjectReferences '<PackageReference Include="Microsoft.AspNetCore.Mvc.Core" />' `
                -ProjectProperties $ProjectProperties -TransitivePinning
        }

        function Get-RestoredLibraries {
            param(
                [Parameter(Mandatory = $true)] [string]$Workspace
            )

            Push-Location -LiteralPath $Workspace
            try {
                $restoreOutput = dotnet restore App.csproj --nologo 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) {
                    throw "Restore failed: $restoreOutput"
                }
                if ($restoreOutput -match 'NU190[05]') {
                    throw "Restore reported missing audit data (NU1900/NU1905): $restoreOutput"
                }

                $assets = Get-Content -LiteralPath (Join-Path $Workspace 'obj\project.assets.json') -Raw | ConvertFrom-Json
                return @($assets.libraries.PSObject.Properties.Name)
            }
            finally {
                Pop-Location
            }
        }

        function Get-NormalAuditVulnerablePackageIds {
            param(
                [Parameter(Mandatory = $true)] [string]$Workspace
            )

            Push-Location -LiteralPath $Workspace
            try {
                $errorPath = [IO.Path]::GetTempFileName()
                try {
                    $json = (dotnet list App.csproj package --vulnerable --include-transitive --format json --output-version 1 2>$errorPath) -join "`n"
                    $listExitCode = $LASTEXITCODE
                    $stderr = Get-Content -LiteralPath $errorPath -Raw
                }
                finally {
                    Remove-Item -LiteralPath $errorPath -Force
                }

                if ($listExitCode -ne 0) {
                    throw 'dotnet list package failed.'
                }
                if ($stderr -and $stderr.Trim()) {
                    throw "dotnet list package wrote to stderr: $stderr"
                }

                $report = $json | ConvertFrom-Json
                if ($report.PSObject.Properties['problems']) {
                    throw 'dotnet list package reported problems, so the baseline is not clean.'
                }
                return @(foreach ($project in $report.projects) {
                    foreach ($framework in @($project.frameworks)) {
                        foreach ($packageList in 'topLevelPackages', 'transitivePackages') {
                            foreach ($package in @($framework.$packageList)) {
                                if ($package.vulnerabilities) {
                                    $package.id
                                }
                            }
                        }
                    }
                })
            }
            finally {
                Pop-Location
            }
        }

        function Invoke-PinCheck {
            param(
                [Parameter(Mandatory = $true)] [string]$Workspace,
                [string]$ScriptPath = $scriptPath
            )

            Push-Location -LiteralPath $Workspace
            try {
                $output = & pwsh -NoProfile -File $ScriptPath -WorkspaceRoot $Workspace -SolutionPath 'App.csproj' 2>&1 | Out-String
                return [pscustomobject]@{
                    ExitCode = $LASTEXITCODE
                    Output = $output
                }
            }
            finally {
                Pop-Location
            }
        }

        function Assert-VulnerablePinStillNeeded {
            param(
                [Parameter(Mandatory = $true)] [string]$Workspace,
                [Parameter(Mandatory = $true)] [string]$ScriptPath
            )

            $packagePath = Join-Path $Workspace 'Directory.Packages.props'
            $before = Get-Content -LiteralPath $packagePath -Raw
            $result = Invoke-PinCheck -Workspace $Workspace -ScriptPath $ScriptPath
            $result.ExitCode | Should -Be 0
            $result.Output | Should -Match 'is still needed'
            $result.Output | Should -Not -Match 'can be removed'
            Get-Content -LiteralPath $packagePath -Raw | Should -Be $before
        }
    }

    AfterAll {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'keeps a vulnerable pin until its removal is checked (<Name>)' -ForEach $auditVariants {
        # Arrange
        $workspace = New-VulnerableWorkspace -Name "vulnerable-$Id" -ProjectProperties $ProjectProperties

        # Act & Assert
        Get-RestoredLibraries -Workspace $workspace | Should -Contain 'Microsoft.AspNetCore.WebUtilities/2.3.14'
        (Get-NormalAuditVulnerablePackageIds -Workspace $workspace).Count | Should -Be 0
        Assert-VulnerablePinStillNeeded -Workspace $workspace -ScriptPath $scriptPath
    }

    It 'fails the vulnerable pin assertion for a mutant that keeps the pin' {
        # Arrange
        $mutantRoot = Join-Path $workRoot 'mutant'
        $null = New-Item -ItemType Directory -Path $mutantRoot -Force
        Copy-Item -LiteralPath $scriptPath -Destination $mutantRoot
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\TemporaryPackagePinAudit.psm1') -Destination $mutantRoot
        $mutantScript = Join-Path $mutantRoot 'Check-TemporaryPackagePins.ps1'
        $source = Get-Content -LiteralPath $mutantScript -Raw
        $mutated = $source.Replace('[void]$_.ParentNode.RemoveChild($_)', '[void]$_')
        $mutated | Should -Not -Be $source
        Set-Content -LiteralPath $mutantScript -Value $mutated -NoNewline
        $workspace = New-VulnerableWorkspace -Name 'vulnerable-mutant'

        # Act
        $result = Invoke-PinCheck -Workspace $workspace -ScriptPath $mutantScript

        # Assert
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'can be removed'
        $result.Output | Should -Not -Match 'Vulnerability audit failed|indeterminate'
    }

    It 'reports a clean pin as removable (<Name>)' -ForEach $auditVariants {
        # Arrange
        $workspace = New-Workspace -Name "clean-$Id" -PackageVersions $cleanPackageVersions `
            -ProjectReferences '<PackageReference Include="Microsoft.Extensions.Logging" />' -ProjectProperties $ProjectProperties

        # Act
        $result = Invoke-PinCheck -Workspace $workspace

        # Assert
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'can be removed'
    }

    It 'keeps the pin unchanged with an indeterminate warning when restore fails without it' {
        # Arrange
        $workspace = New-Workspace -Name 'restore-fails' -PackageVersions @'
    <!-- TEMP-PIN: test -->
    <PackageVersion Include="Serilog" Version="4.2.0" />
'@ -ProjectReferences '<PackageReference Include="Serilog" />'
        $packagePath = Join-Path $workspace 'Directory.Packages.props'
        $before = Get-Content -LiteralPath $packagePath -Raw

        # Act
        $result = Invoke-PinCheck -Workspace $workspace

        # Assert
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match '::warning title=Temporary pin indeterminate::'
        $result.Output | Should -Not -Match 'can be removed'
        Get-Content -LiteralPath $packagePath -Raw | Should -Be $before
    }

    It 'fails closed when the audit source provides no vulnerability data (NU1905)' {
        # Arrange
        $emptyAuditSource = Join-Path $workRoot 'empty-audit-source'
        $null = New-Item -ItemType Directory -Path $emptyAuditSource -Force
        $nuGetConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <auditSources>
    <clear />
    <add key="empty" value="$emptyAuditSource" />
  </auditSources>
</configuration>
"@
        $workspace = New-Workspace -Name 'audit-source-empty' -PackageVersions $cleanPackageVersions `
            -ProjectReferences '<PackageReference Include="Microsoft.Extensions.Logging" />' -NuGetConfig $nuGetConfig

        # Act
        $result = Invoke-PinCheck -Workspace $workspace

        # Assert
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'Vulnerability audit failed'
        $result.Output | Should -Not -Match 'can be removed'
    }
}
