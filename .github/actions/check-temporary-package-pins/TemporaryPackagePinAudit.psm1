function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if (($null -eq $property) -or ($null -eq $property.Value)) {
        throw "Audit report is missing required property '$Name'."
    }

    return ,$property.Value
}

function Get-OptionalArray {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return @()
    }

    if ($property.Value -isnot [System.Array]) {
        throw "Audit report property '$Name' must be an array."
    }

    return $property.Value
}

function Get-AuditVulnerabilityCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$StandardOutput,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$StandardError
    )

    if ($ExitCode -ne 0) {
        throw "dotnet list package exited with code $ExitCode."
    }

    if ("$StandardOutput`n$StandardError" -match 'NU190[0-5]') {
        throw 'NuGet reported an audit warning (NU1900-NU1905): the vulnerability result is not conclusive.'
    }

    if ([string]::IsNullOrWhiteSpace($StandardOutput)) {
        throw 'dotnet list package produced no JSON report.'
    }

    $report = $StandardOutput | ConvertFrom-Json -ErrorAction Stop
    if ([int](Get-RequiredProperty -InputObject $report -Name 'version') -ne 1) {
        throw 'Audit report has an unsupported version.'
    }

    $problems = $report.PSObject.Properties['problems']
    if (($null -ne $problems) -and (($problems.Value -isnot [System.Array]) -or ($problems.Value.Count -gt 0))) {
        throw 'Audit report contains problems (for example NU1905: an audit source provided no vulnerability data).'
    }

    $parameters = [string](Get-RequiredProperty -InputObject $report -Name 'parameters')
    if (($parameters -notmatch '--vulnerable') -or ($parameters -notmatch '--include-transitive')) {
        throw 'Audit report does not state that it was created with --vulnerable and --include-transitive.'
    }

    $projects = Get-RequiredProperty -InputObject $report -Name 'projects'
    if ($projects -isnot [System.Array]) {
        throw "Audit report property 'projects' must be an array."
    }

    if ($projects.Count -eq 0) {
        throw 'Audit report contains no projects.'
    }

    $vulnerabilityCount = 0
    foreach ($project in $projects) {
        $null = Get-RequiredProperty -InputObject $project -Name 'path'
        foreach ($framework in Get-OptionalArray -InputObject $project -Name 'frameworks') {
            $null = Get-RequiredProperty -InputObject $framework -Name 'framework'
            foreach ($packageList in 'topLevelPackages', 'transitivePackages') {
                foreach ($package in Get-OptionalArray -InputObject $framework -Name $packageList) {
                    $null = Get-RequiredProperty -InputObject $package -Name 'id'
                    $vulnerabilities = Get-RequiredProperty -InputObject $package -Name 'vulnerabilities'
                    if (($vulnerabilities -isnot [System.Array]) -or ($vulnerabilities.Count -eq 0)) {
                        throw "Audit report package '$($package.id)' must list at least one vulnerability."
                    }

                    $vulnerabilityCount += $vulnerabilities.Count
                }
            }
        }
    }

    return $vulnerabilityCount
}

Export-ModuleMember -Function Get-AuditVulnerabilityCount
