<#
.SYNOPSIS
    Parses an Infoblox network CSV, converts Address+Netmask to CIDR,
    then creates Zero Networks custom groups named "Site_<EA-Site>" and
    adds the corresponding network asset IDs as group members via the API.
 
.PARAMETER CsvPath
    Path to the Infoblox network CSV export.
 
.PARAMETER BaseApiUrl
    Zero Networks API base URL. Example: "https://portal.zeronetworks.com/api/v1"
 
.PARAMETER ApiKey
    API key for Zero Networks authentication.
 
.PARAMETER ShowUnusedEASite
    If set, processes networks with blank EA-Site (grouped as "Unused-EA-SITE").
    Default: $false (skipped).
 
.PARAMETER ThrottleMs
    Milliseconds to wait between API calls when resolving CIDRs.
    Default: 150. Increase if you see 502 errors on large site groups.
 
.PARAMETER WhatIf
    If set, performs a dry run -- parses CSV and logs intended actions without
    making any API calls.
 
.EXAMPLE
    .\Create-SiteGroups.ps1 -CsvPath './dl-nets-export-20250126.csv' `
        -BaseApiUrl 'https://portal.zeronetworks.com/api/v1' `
        -ApiKey 'your_api_key' -WhatIf
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,
 
    [Parameter(Mandatory = $true)]
    [string]$BaseApiUrl,
 
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
 
    [Parameter(Mandatory = $false)]
    [switch]$ShowUnusedEASite = $false,
 
    [Parameter(Mandatory = $false)]
    [int]$ThrottleMs = 150,
 
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf = $false
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
# --- Helper Functions ---
 
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry }
    }
}

function Convert-NetmaskToCIDR {
    param([Parameter(Mandatory)][string]$Netmask)
    $octets = $Netmask.Split('.')
    if ($octets.Count -ne 4) { throw "Invalid netmask: '$Netmask'" }
    $bits = 0
    foreach ($octet in $octets) {
        switch ([int]$octet) {
            255 { $bits += 8 } 254 { $bits += 7 } 252 { $bits += 6 }
            248 { $bits += 5 } 240 { $bits += 4 } 224 { $bits += 3 }
            192 { $bits += 2 } 128 { $bits += 1 } 0   { $bits += 0 }
            default { throw "Non-contiguous netmask octet: $octet" }
        }
    }
    return $bits
}

function Resolve-NetworkAssetId {
    param(
        [Parameter(Mandatory)][string]$CIDR,
        [Parameter(Mandatory)][string]$BaseApiUrl,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $encodedCIDR  = [System.Uri]::EscapeDataString($CIDR)
    $candidateUri = "$BaseApiUrl/groups/custom/member-candidates?_search=$encodedCIDR&_limit=100"
 
    try {
        # Use Invoke-WebRequest + UseBasicParsing to avoid IE engine dependency
        # and capture raw content for troubleshooting
        $response = Invoke-WebRequest -Uri $candidateUri -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
        
        # Verify we actually got JSON back
        if ($response.Content -match '^\s*\{|\[') {
            $results = $response.Content | ConvertFrom-Json
            if ($results.items) {
                foreach ($item in @($results.items)) {
                    # Skip groups (entityType 3 or 4) to avoid cross-site pollution
                    if ($item.entityType -in @(3, 4)) { continue }
                    if ($item.name -eq $CIDR) { return $item.id }
                }
            }
        } else {
            Write-Log "Non-JSON response received for CIDR '$CIDR'. Possible Proxy/WAF interference." -Level ERROR
            Write-Log "Raw Content Snippet: $($response.Content.Substring(0, [Math]::Min(200, $response.Content.Length)))" -Level WARNING
        }
    }
    catch {
        Write-Log "Failed to resolve CIDR '$CIDR': $($_.Exception.Message)" -Level ERROR
        # Safe check for Response object to prevent "Property not found" error
        if ($null -ne $_.Exception.InternalException -and $null -ne $_.Exception.InternalException.Response) {
             $resp = $_.Exception.InternalException.Response
             $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
             Write-Log "Server Error Detail: $($reader.ReadToEnd())" -Level WARNING
        }
    }
    return $null
}

function Ensure-GroupExists {
    param([string]$GroupName, [string]$BaseApiUrl, [hashtable]$Headers)
    $result = @{ GroupID = $null; NewlyCreated = $false }
    Write-Log "Checking if group '$GroupName' exists..."
    
    $filterValue = '[{"id":"name","includeValues":["' + $GroupName + '"],"excludeValues":[]}]'
    $encodedFilter = [System.Uri]::EscapeDataString($filterValue)
    $checkGroupUri = "$BaseApiUrl/groups/custom?_limit=1&_filters=$encodedFilter"

    try {
        $response = Invoke-WebRequest -Uri $checkGroupUri -Method Get -Headers $Headers -UseBasicParsing
        $data = $response.Content | ConvertFrom-Json
        if ($data.items -and @($data.items).Count -gt 0) {
            $result.GroupID = @($data.items)[0].id
            Write-Log "Group '$GroupName' found with ID: $($result.GroupID)"
            return $result
        }
    } catch { 
        Write-Log "Error checking group existence: $($_.Exception.Message)" -Level ERROR
        return $result 
    }

    Write-Log "Group '$GroupName' not found. Creating..."
    $body = @{ name = $GroupName; description = "Auto-created Site Group"; membersId = @() } | ConvertTo-Json
    try {
        $response = Invoke-WebRequest -Uri "$BaseApiUrl/groups/custom" -Method Post -Headers $Headers -Body $body -UseBasicParsing
        $data = $response.Content | ConvertFrom-Json
        if ($data.entity.id) {
            $result.GroupID = $data.entity.id
            $result.NewlyCreated = $true
            Write-Log "Group '$GroupName' created: $($result.GroupID)" -Level SUCCESS
        }
    } catch { Write-Log "Failed to create group: $($_.Exception.Message)" -Level ERROR }
    
    return $result
}

function Get-ExistingGroupMembers {
    param([string]$GroupID, [string]$BaseApiUrl, [hashtable]$Headers)
    $existingIds = [System.Collections.Generic.HashSet[string]]::new()
    $offset = 0; $limit = 400
    do {
        $uri = "$BaseApiUrl/groups/custom/$GroupID/members?_limit=$limit&_offset=$offset"
        $resp = Invoke-WebRequest -Uri $uri -Method Get -Headers $Headers -UseBasicParsing
        $data = $resp.Content | ConvertFrom-Json
        $page = @($data.items)
        foreach ($item in $page) { if ($item.id) { [void]$existingIds.Add([string]$item.id) } }
        $offset += $limit
    } while ($page.Count -eq $limit)
    return $existingIds
}

# --- Main Logic ---
Write-Log "Starting Create-SiteGroups script..."
$apiHeaders = @{ "Authorization" = $ApiKey; "Content-Type" = "application/json" }

Write-Log "Reading CSV: $CsvPath"
$lines = Get-Content -Path $CsvPath -Encoding UTF8
$lines[0] = $lines[0] -replace '\*', ''
$raw = @($lines | ConvertFrom-Csv)

$activeNetworks = New-Object System.Collections.Generic.List[PSCustomObject]
foreach ($row in $raw) {
    if ($row.disabled -ine 'FALSE') { continue }
    try {
        $prefix = Convert-NetmaskToCIDR -Netmask $row.netmask
        $activeNetworks.Add([PSCustomObject]@{
            CIDR   = "$($row.address)/$prefix"
            EASite = if ($null -ne $row.'EA-Site') { $row.'EA-Site'.Trim() } else { 'Unused-EA-SITE' }
        })
    } catch { Write-Log "Skipping $($row.address): $($_.Exception.Message)" -Level WARNING }
}

$bySite = $activeNetworks | Group-Object -Property EASite | Where-Object { $ShowUnusedEASite -or $_.Name -ne 'Unused-EA-SITE' }

foreach ($siteGroup in $bySite) {
    $groupName = "Site_$($siteGroup.Name)"
    Write-Log "Processing Group: $groupName"
    
    if ($WhatIf) { Write-Log "[WHATIF] Would process $groupName"; continue }

    $target = Ensure-GroupExists -GroupName $groupName -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
    if (-not $target.GroupID) { continue }

    $existingMembers = Get-ExistingGroupMembers -GroupID $target.GroupID -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
    $uniqueCidrs = @($siteGroup.Group | Select-Object -ExpandProperty CIDR -Unique)
    
    $toAdd = New-Object System.Collections.Generic.List[string]
    foreach ($cidr in $uniqueCidrs) {
        $assetId = Resolve-NetworkAssetId -CIDR $cidr -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
        Start-Sleep -Milliseconds $ThrottleMs
        if ($assetId -and -not $existingMembers.Contains($assetId)) { [void]$toAdd.Add($assetId) }
    }

    if ($toAdd.Count -gt 0) {
        Write-Log "Adding $($toAdd.Count) new members to $groupName..."
        $body = @{ membersId = $toAdd } | ConvertTo-Json
        Invoke-WebRequest -Uri "$BaseApiUrl/groups/custom/$($target.GroupID)/members" -Method Put -Headers $apiHeaders -Body $body -UseBasicParsing
        Write-Log "Update complete for $groupName" -Level SUCCESS
    } else {
        Write-Log "No new members to add for $groupName"
    }
}
Write-Log "Script finished."