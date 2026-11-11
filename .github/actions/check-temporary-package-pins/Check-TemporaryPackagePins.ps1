[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceRoot,

    [Parameter(Mandatory = $true)]
    [string]$SolutionPath,

    [Parameter(Mandatory = $false)]
    [string]$PackageFile = 'Directory.Packages.props',

    [Parameter(Mandatory = $false)]
    [string]$PinMarker = 'TEMP-PIN:'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

function Fail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "::error title=$Title::$Message"
    exit 1
}

function Get-DotnetSdkVersion {
    $versionOutput = (& dotnet --version 2>&1) -join [Environment]::NewLine
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Fail -Title 'Temporary pin guard failed' -Message "Could not determine the .NET SDK version. Exit code: $exitCode. Output: $versionOutput"
    }

    if ($versionOutput.Trim() -notmatch '^(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.-]+)?$') {
        Fail -Title 'Temporary pin guard failed' -Message "The .NET SDK returned an invalid version '$($versionOutput.Trim())'."
    }

    $sdkVersion = [version]$Matches[1]
    if ($sdkVersion -lt [version]'9.0.300') {
        Fail -Title 'Temporary pin guard misconfigured' -Message "The vulnerability JSON report requires .NET SDK 9.0.300 or later; found '$sdkVersion'."
    }

    return $sdkVersion
}

function Get-VulnerabilityFindings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SolutionPath,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    $auditOutput = (& dotnet list $SolutionPath package --vulnerable --include-transitive --format json --output-version 1 --no-restore 2>&1) -join [Environment]::NewLine
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit failed for '$PackageName'. Exit code: $exitCode. Output: $auditOutput"
    }

    if ($auditOutput -match '\bNU1900\b') {
        Fail -Title 'Vulnerability audit failed' -Message "Dotnet audit could not retrieve vulnerability data for '$PackageName'. Output: $auditOutput"
    }

    try {
        $report = ConvertFrom-Json -InputObject $auditOutput -ErrorAction Stop
    }
    catch {
        Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' did not return valid JSON. Output: $auditOutput"
    }

    if ($report.version -ne 1 -or
        $null -eq $report.projects -or
        [string]::IsNullOrWhiteSpace($report.parameters) -or
        $report.parameters -notmatch '--vulnerable' -or
        $report.parameters -notmatch '--include-transitive' -or
        @($report.projects).Count -eq 0) {
        Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' returned an unsupported or incomplete JSON report."
    }

    $findings = [System.Collections.Generic.List[string]]::new()
    foreach ($project in @($report.projects)) {
        if ($null -eq $project.path) {
            Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' returned a project without a path."
        }

        if ($null -eq $project.frameworks) {
            continue
        }

        foreach ($framework in @($project.frameworks)) {
            if ([string]::IsNullOrWhiteSpace($framework.framework)) {
                Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' returned a target framework without a name."
            }

            foreach ($packageCollectionName in @('topLevelPackages', 'transitivePackages')) {
                $packageCollection = $framework.$packageCollectionName
                if ($null -eq $packageCollection) {
                    continue
                }

                foreach ($package in @($packageCollection)) {
                    if ([string]::IsNullOrWhiteSpace($package.id) -or
                        [string]::IsNullOrWhiteSpace($package.resolvedVersion) -or
                        $null -eq $package.vulnerabilities) {
                        Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' returned an incomplete package record."
                    }

                    foreach ($vulnerability in @($package.vulnerabilities)) {
                        if ([string]::IsNullOrWhiteSpace($vulnerability.severity) -or
                            [string]::IsNullOrWhiteSpace($vulnerability.advisoryurl)) {
                            Fail -Title 'Vulnerability audit failed' -Message "Dotnet vulnerability audit for '$PackageName' returned an incomplete vulnerability record."
                        }

                        $findings.Add((@(
                            [string]$project.path
                            [string]$framework.framework
                            [string]$package.id
                            [string]$package.resolvedVersion
                            [string]$vulnerability.severity
                            [string]$vulnerability.advisoryurl
                        ) -join "`n"))
                    }
                }
            }
        }
    }

    return $findings
}

function Find-DirectPackageReference {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceRoot,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    try {
        $configurationFiles = @(
            Get-ChildItem -LiteralPath $WorkspaceRoot -Force -Recurse -File -ErrorAction Stop |
                Where-Object {
                    $relativePath = [IO.Path]::GetRelativePath($WorkspaceRoot, $_.FullName)
                    $pathSegments = $relativePath -split '[\\/]'
                    $_.Extension -in @('.csproj', '.vbproj', '.fsproj', '.props', '.targets') -and
                    $pathSegments -notcontains '.git' -and
                    $pathSegments -notcontains 'bin' -and
                    $pathSegments -notcontains 'obj'
                } |
                Sort-Object -Property FullName
        )
    }
    catch {
        Fail -Title 'Temporary pin check failed' -Message "Could not inspect project and build files for direct PackageReference items: $($_.Exception.Message)"
    }

    foreach ($configurationFile in $configurationFiles) {
        try {
            [xml]$document = Get-Content -LiteralPath $configurationFile.FullName -Raw -ErrorAction Stop
        }
        catch {
            Fail -Title 'Temporary pin check failed' -Message "Could not parse build file '$($configurationFile.FullName)' while checking direct PackageReference items."
        }

        foreach ($packageReference in @($document.SelectNodes("//*[local-name()='PackageReference']"))) {
            foreach ($attributeName in @('Include', 'Update')) {
                if (-not $packageReference.HasAttribute($attributeName)) {
                    continue
                }

                foreach ($referencedPackage in @($packageReference.GetAttribute($attributeName) -split ';' | ForEach-Object { $_.Trim() })) {
                    if ($referencedPackage -ine $PackageName) {
                        continue
                    }

                    $isConditional = $false
                    $currentNode = $packageReference
                    while ($null -ne $currentNode -and $currentNode.NodeType -eq [Xml.XmlNodeType]::Element) {
                        $conditionAttribute = $currentNode.Attributes['Condition']
                        if ($null -ne $conditionAttribute -and -not [string]::IsNullOrWhiteSpace($conditionAttribute.Value)) {
                            $isConditional = $true
                        }

                        $currentNode = $currentNode.ParentNode
                    }

                    return [PSCustomObject]@{
                        Path = [IO.Path]::GetRelativePath($WorkspaceRoot, $configurationFile.FullName)
                        Operation = $attributeName
                        IsConditional = $isConditional
                    }
                }
            }
        }
    }

    return $null
}

function Test-MatchingPackageVersionDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DiagnosticLine,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    $diagnosticPattern = '(?i)\bNU1010:\s*The following PackageReference items do not define a corresponding PackageVersion item:\s*(?<packageNames>.+?)\.\s*Projects using Central Package Management'
    if ($DiagnosticLine -notmatch $diagnosticPattern) {
        return $false
    }

    $packageNames = @($Matches['packageNames'] -split '\s*,\s*' | ForEach-Object { $_.Trim() })
    return $packageNames.Count -eq 1 -and $packageNames[0] -ieq $PackageName
}

function Test-PurePackageVersionRestoreFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RestoreOutput,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    $restoreLines = @($RestoreOutput -split '[\r\n]+')
    $errorLines = @($restoreLines | Where-Object { $_ -match '(?i)\berror\b' })
    if ($errorLines.Count -eq 0) {
        return $false
    }

    foreach ($errorLine in $errorLines) {
        if (-not (Test-MatchingPackageVersionDiagnostic -DiagnosticLine $errorLine -PackageName $PackageName)) {
            return $false
        }
    }

    foreach ($diagnosticLine in @($restoreLines | Where-Object { $_ -match '\bNU1010\b' })) {
        if (-not (Test-MatchingPackageVersionDiagnostic -DiagnosticLine $diagnosticLine -PackageName $PackageName)) {
            return $false
        }
    }

    return $true
}

function Invoke-VerifiedRestore {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SolutionPath,

        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $true)]
        [string]$Scenario,

        [Parameter(Mandatory = $false)]
        [switch]$AllowMissingPackageVersion
    )

    $restoreOutput = (& dotnet restore $SolutionPath --nologo '-p:RestoreLockedMode=false' 2>&1) -join [Environment]::NewLine
    $exitCode = $LASTEXITCODE

    if ($restoreOutput -match '\bNU1900\b') {
        Fail -Title 'Vulnerability audit failed' -Message "Dotnet restore could not retrieve vulnerability data for '$PackageName'. Output: $restoreOutput"
    }

    if ($exitCode -ne 0) {
        if ($AllowMissingPackageVersion -and
            $exitCode -eq 1 -and
            (Test-PurePackageVersionRestoreFailure -RestoreOutput $restoreOutput -PackageName $PackageName)) {
            return [PSCustomObject]@{
                Status = 'Indeterminate'
                Message = "Could not classify temporary pin '$PackageName': removing it causes NU1010 only for its matching PackageReference. The pin was left unchanged."
            }
        }

        Fail -Title 'Temporary pin check failed' -Message "Restore failed $Scenario for temporary pin '$PackageName'; the pin cannot be classified as needed or removable. Exit code: $exitCode. Output: $restoreOutput"
    }

    if ($restoreOutput -match '(?i)\berror\b') {
        Fail -Title 'Temporary pin check failed' -Message "Restore reported errors for temporary pin '$PackageName' despite exiting successfully. Output: $restoreOutput"
    }

    return [PSCustomObject]@{ Status = 'Succeeded' }
}

function Test-PinRemovable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceRoot,

        [Parameter(Mandatory = $true)]
        [string]$SolutionRelativePath,

        [Parameter(Mandatory = $true)]
        [string]$PackageRelativePath,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    $nativePreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("mu88-temp-pin-" + [guid]::NewGuid().ToString('N'))

    try {
        $null = Get-DotnetSdkVersion
        $null = New-Item -ItemType Directory -Path $tempRoot

        Get-ChildItem -LiteralPath $WorkspaceRoot -Force |
            Where-Object { $_.Name -ne '.git' } |
            ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $tempRoot -Recurse -Force }

        $tempSolutionPath = Join-Path $tempRoot $SolutionRelativePath
        $null = Invoke-VerifiedRestore -SolutionPath $tempSolutionPath -PackageName $PackageName -Scenario 'with the pin present'
        $baselineFindings = Get-VulnerabilityFindings -SolutionPath $tempSolutionPath -PackageName $PackageName

        $directPackageReference = Find-DirectPackageReference -WorkspaceRoot $tempRoot -PackageName $PackageName
        if ($null -ne $directPackageReference) {
            $declarationState = if ($directPackageReference.IsConditional) { 'conditional declaration; its condition was not evaluated' } else { 'explicit declaration' }
            return [PSCustomObject]@{
                Removable = $false
                Indeterminate = $true
                Message = "Could not classify temporary pin '$PackageName': PackageReference $($directPackageReference.Operation) in '$($directPackageReference.Path)' is an exact $declarationState. The pin was left unchanged and the candidate restore was skipped."
            }
        }

        $tempPackagePath = Join-Path $tempRoot $PackageRelativePath
        [xml]$packageDocument = Get-Content -LiteralPath $tempPackagePath -Raw
        @($packageDocument.SelectNodes("//*[local-name()='PackageVersion' and @Include='$PackageName']")) |
            ForEach-Object { [void]$_.ParentNode.RemoveChild($_) }
        Set-Content -LiteralPath $tempPackagePath -Value $packageDocument.OuterXml -Encoding utf8NoBOM

        $candidateRestore = Invoke-VerifiedRestore -SolutionPath $tempSolutionPath -PackageName $PackageName -Scenario 'after removing it' -AllowMissingPackageVersion
        if ($candidateRestore.Status -eq 'Indeterminate') {
            return [PSCustomObject]@{
                Removable = $false
                Indeterminate = $true
                Message = $candidateRestore.Message
            }
        }

        $candidateFindings = Get-VulnerabilityFindings -SolutionPath $tempSolutionPath -PackageName $PackageName
        $baselineFindingSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($finding in $baselineFindings) {
            $null = $baselineFindingSet.Add($finding)
        }

        foreach ($finding in $candidateFindings) {
            if (-not $baselineFindingSet.Contains($finding)) {
                return [PSCustomObject]@{
                    Removable = $false
                    Indeterminate = $false
                }
            }
        }

        return [PSCustomObject]@{
            Removable = $true
            Indeterminate = $false
        }
    }
    finally {
        $PSNativeCommandUseErrorActionPreference = $nativePreference
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

$resolvedPackagePath = if ([IO.Path]::IsPathRooted($PackageFile)) { $PackageFile } else { Join-Path $WorkspaceRoot $PackageFile }
$resolvedSolutionPath = if ([IO.Path]::IsPathRooted($SolutionPath)) { $SolutionPath } else { Join-Path $WorkspaceRoot $SolutionPath }

if (-not (Test-Path -LiteralPath $resolvedPackagePath)) {
    Fail -Title 'Temporary pin guard misconfigured' -Message "Package file '$PackageFile' was not found."
}

if (-not (Test-Path -LiteralPath $resolvedSolutionPath)) {
    Fail -Title 'Temporary pin guard misconfigured' -Message "Solution path '$SolutionPath' was not found."
}

$packageRelativePath = [IO.Path]::GetRelativePath($WorkspaceRoot, $resolvedPackagePath)
$solutionRelativePath = [IO.Path]::GetRelativePath($WorkspaceRoot, $resolvedSolutionPath)

[xml]$document = Get-Content -LiteralPath $resolvedPackagePath -Raw
$pins = [System.Collections.Generic.List[pscustomobject]]::new()
$pendingMarker = $false

foreach ($itemGroup in @($document.Project.ItemGroup)) {
    foreach ($node in @($itemGroup.ChildNodes)) {
        if ($node.NodeType -eq [Xml.XmlNodeType]::Comment) {
            if ($node.Value -match [regex]::Escape($PinMarker)) {
                $pendingMarker = $true
            }

            continue
        }

        if ($node.NodeType -ne [Xml.XmlNodeType]::Element) {
            continue
        }

        if (-not $pendingMarker) {
            continue
        }

        if ($node.LocalName -ne 'PackageVersion') {
            Fail -Title 'Temporary pin guard misconfigured' -Message "Marker '$PinMarker' must be followed by a PackageVersion element in '$PackageFile'."
        }

        $pins.Add([pscustomobject]@{
            Name = $node.GetAttribute('Include')
            Version = $node.GetAttribute('Version')
        })
        $pendingMarker = $false
    }
}

if ($pendingMarker) {
    Fail -Title 'Temporary pin guard misconfigured' -Message "Marker '$PinMarker' at the end of '$PackageFile' is missing a following PackageVersion element."
}

if ($pins.Count -eq 0) {
    Write-Host 'No temporary package pins found.'
    exit 0
}

foreach ($pin in $pins) {
    $pinResult = Test-PinRemovable -WorkspaceRoot $WorkspaceRoot -SolutionRelativePath $solutionRelativePath -PackageRelativePath $packageRelativePath -PackageName $pin.Name
    if ($pinResult.Removable) {
        Fail -Title 'Remove temporary pin' -Message "Temporary pin '$($pin.Name)' ($($pin.Version)) can be removed. Removing it introduces no new vulnerability findings."
    }

    if ($pinResult.Indeterminate) {
        Write-Host "::warning title=Temporary pin check inconclusive::$($pinResult.Message)"
        continue
    }

    Write-Host "Temporary pin '$($pin.Name)' ($($pin.Version)) is still needed."
}

exit 0
