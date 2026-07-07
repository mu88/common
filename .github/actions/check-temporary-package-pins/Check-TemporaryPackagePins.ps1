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

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("mu88-temp-pin-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $tempRoot

    try {
        Get-ChildItem -LiteralPath $WorkspaceRoot -Force |
            Where-Object { $_.Name -ne '.git' } |
            ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $tempRoot -Recurse -Force }

        $tempPackagePath = Join-Path $tempRoot $PackageRelativePath
        [xml]$packageDocument = Get-Content -LiteralPath $tempPackagePath -Raw
        @($packageDocument.SelectNodes("//*[local-name()='PackageVersion' and @Include='$PackageName']")) |
            ForEach-Object { [void]$_.ParentNode.RemoveChild($_) }
        Set-Content -LiteralPath $tempPackagePath -Value $packageDocument.OuterXml -Encoding utf8NoBOM

        $tempSolutionPath = Join-Path $tempRoot $SolutionRelativePath
        $nativePreference = $PSNativeCommandUseErrorActionPreference
        try {
            $PSNativeCommandUseErrorActionPreference = $false
            $null = & dotnet restore $tempSolutionPath --nologo 2>&1
            if ($LASTEXITCODE -ne 0) {
                return $false
            }

            $auditOutput = (& dotnet list $tempSolutionPath package --vulnerable --include-transitive 2>&1) -join [Environment]::NewLine
            if (($auditOutput -match 'NU1900') -and ($auditOutput -notmatch 'NU190[1-4]')) {
                Fail -Title 'Vulnerability audit failed' -Message "Dotnet audit could not retrieve vulnerability data for '$PackageName'."
            }

            return $auditOutput -notmatch 'NU190[1-4]'
        }
        finally {
            $PSNativeCommandUseErrorActionPreference = $nativePreference
        }
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
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
    if (Test-PinRemovable -WorkspaceRoot $WorkspaceRoot -SolutionRelativePath $solutionRelativePath -PackageRelativePath $packageRelativePath -PackageName $pin.Name) {
        Fail -Title 'Remove temporary pin' -Message "Temporary pin '$($pin.Name)' ($($pin.Version)) can be removed. Restore and vulnerability scan stay clean without it."
    }

    Write-Host "Temporary pin '$($pin.Name)' ($($pin.Version)) is still needed."
}

exit 0
