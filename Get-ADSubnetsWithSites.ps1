 <#
.SYNOPSIS
    Retrieves all AD sites and subnets, providing clear mapping between subnet and site.
.DESCRIPTION
    Queries Active Directory using the AD PowerShell module to list each subnet and its associated site.
    Supports export to CSV for inventory, documentation, or verification against networking config.
.EXAMPLE
    .\Get-ADSubnetsWithSites.ps1
.EXAMPLE
    .\Get-ADSubnetsWithSites.ps1 -ExportPath "C:\Reports\AD_Subnets.csv"
.NOTES
    Requires the ActiveDirectory module (install RSAT or import on a domain-joined system).
    Run with appropriate privileges to query AD topology.
#>

[CmdletBinding()]
param(
    [string]$ExportPath
)

# Ensure the ActiveDirectory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or import the module before running."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Query all subnets
$subnets = Get-ADReplicationSubnet -Filter * -Properties SiteObject, Site

# Validate results
if (-not $subnets) {
    Write-Warning "No AD subnets found in the directory."
    return
}

# Prepare output
$results = $subnets | ForEach-Object {
    $siteDN = $_.Site
    $siteName = if ($siteDN) {
        try {
            # Retrieve readable site name
            ($siteDN -split ',')[0] -replace '^CN='
        } catch {
            'Unknown'
        }
    } else {
        'Unassigned'
    }

    [PSCustomObject]@{
        Sitename = $siteName
        Subnet   = $_.Name
    }
}

# Display results in table format
$results | Sort-Object Sitename, Subnet | Format-Table -AutoSize

# Optional CSV export
if ($ExportPath) {
    try {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export results: $_"
    }
} 
