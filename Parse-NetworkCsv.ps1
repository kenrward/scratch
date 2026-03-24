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

    [int]$ThrottleMs = 150,

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
            255 { $bits += 8 }
            254 { $bits += 7 }
            252 { $bits += 6 }
            248 { $bits += 5 }
            240 { $bits += 4 }
            224 { $bits += 3 }
            192 { $bits += 2 }
            128 { $bits += 1 }
            0   { $bits += 0 }
            default { throw "Non-contiguous netmask octet: $octet in '$Netmask'" }
        }
    }
    return $bits
}

function Ensure-GroupExists {
    param([string]$GroupName, [string]$BaseApiUrl, [hashtable]$Headers)
    $result = @{ GroupID = $null; NewlyCreated = $false }
    Write-Log "Checking if group '$GroupName' exists..."
    
    $filterValue = '[{"id":"name","includeValues":["' + $GroupName + '"],"excludeValues":[]}]'
    $encodedFilter = [System.Uri]::EscapeDataString($filterValue)
    $checkGroupUri = "$BaseApiUrl/groups/custom?_limit=1&_filters=$encodedFilter"

    try {
        $existingGroupResponse = Invoke-RestMethod -Uri $checkGroupUri -Method Get -Headers $Headers
        if ($null -ne $existingGroupResponse -and $existingGroupResponse.PSObject.Properties['items'] -and @($existingGroupResponse.items).Count -gt 0) {
            $result.GroupID = @($existingGroupResponse.items)[0].id
            Write-Log "Group '$GroupName' found with ID: $($result.GroupID)"
            return $result
        }
    } catch {
        Write-Log "Error checking group existence: $($_.Exception.Message)" -Level WARNING
    }

    Write-Log "Group '$GroupName' not found. Creating..."
    $createGroupUri = "$BaseApiUrl/groups/custom"
    $createGroupBody = @{
        name        = $GroupName
        description = "Site group for $GroupName (auto-created by script)"
        membersId   = @()
    } | ConvertTo-Json -Depth 5

    $newGroupResponse = Invoke-RestMethod -Uri $createGroupUri -Method Post -Headers $Headers -Body $createGroupBody
    if ($null -ne $newGroupResponse -and $newGroupResponse.PSObject.Properties['entity'] -and $newGroupResponse.entity.id) {
        $result.GroupID = $newGroupResponse.entity.id
        $result.NewlyCreated = $true
        Write-Log "Group '$GroupName' created with ID: $($result.GroupID)" -Level SUCCESS
    } else {
        Write-Log "Failed to create group '$GroupName'." -Level ERROR
    }
    return $result
}

function Verify-GroupExists {
    param([string]$GroupName, [string]$GroupID, [string]$BaseApiUrl, [hashtable]$Headers, [int]$MaxRetries = 3, [int]$RetryDelaySeconds = 3)
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Log "Verifying group '$GroupName' (ID: $GroupID), attempt $attempt of $MaxRetries..."
        try {
            $verifyUri = "$BaseApiUrl/groups/custom/$GroupID"
            $response = Invoke-RestMethod -Uri $verifyUri -Method Get -Headers $Headers
            if ($null -ne $response -and $response.PSObject.Properties['entity'] -and $response.entity.id -eq $GroupID) {
                Write-Log "Group '$GroupName' (ID: $GroupID) verified." -Level SUCCESS
                return $true
            }
        } catch {
            Write-Log "Verification attempt $attempt failed: $($_.Exception.Message)" -Level WARNING
        }
        if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
    return $false
}

function Get-ExistingGroupMembers {
    param([Parameter(Mandatory)][string]$GroupID, [Parameter(Mandatory)][string]$BaseApiUrl, [Parameter(Mandatory)][hashtable]$Headers)
    $existingIds = [System.Collections.Generic.HashSet[string]]::new()
    $offset = 0; $limit = 400
    do {
        $uri = "$BaseApiUrl/groups/custom/$GroupID/members?_limit=$limit&_offset=$offset"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers
        
        # Safety check for 'items' property
        if ($null -ne $response -and $response.PSObject.Properties['items']) {
            $page = @($response.items)
            foreach ($item in $page) {
                if ($null -ne $item.id -and $item.id -ne '') { [void]$existingIds.Add([string]$item.id) }
            }
        } else { $page = @() }
        $offset += $limit
    } while ($page.Count -eq $limit)
    return $existingIds
}

function Resolve-NetworkAssetId {
    param([Parameter(Mandatory)][string]$CIDR, [Parameter(Mandatory)][string]$BaseApiUrl, [Parameter(Mandatory)][hashtable]$Headers)
    
    $excludedEntityTypes = @(3, 4)
    $encodedCIDR  = [System.Uri]::EscapeDataString($CIDR)
    $candidateUri = "$BaseApiUrl/groups/custom/member-candidates?_search=$encodedCIDR&_limit=100&_offset=0"
    $maxRetries = 4; $retryDelay = 2

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $results = Invoke-RestMethod -Uri $candidateUri -Method Get -Headers $Headers
            if ($null -ne $results -and $results.PSObject.Properties['items'] -and @($results.items).Count -gt 0) {
                foreach ($item in @($results.items)) {
                    $itemName = if ($null -ne $item.name) { [string]$item.name } else { '' }
                    $itemEntityType = if ($null -ne $item.entityType) { [int]$item.entityType } else { -1 }
                    if ($itemEntityType -in $excludedEntityTypes) { continue }
                    if ($itemName -eq $CIDR) { return $item.id }
                }
                return $null
            }
            return $null
        } catch {
            # Robust check for Status Code
            $statusCode = 0
            if ($null -ne $_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            
            if ($statusCode -in @(429, 502, 503, 504) -and $attempt -lt $maxRetries) {
                Write-Log "  Transient $statusCode for '$CIDR'. Retry $attempt/$maxRetries in ${retryDelay}s..." -Level WARNING
                Start-Sleep -Seconds $retryDelay
                $retryDelay *= 2
            } else {
                Write-Log "  Failed to resolve asset ID for CIDR '$CIDR': $($_.Exception.Message)" -Level ERROR
                return $null
            }
        }
    }
    return $null
}

# --- MAIN SCRIPT ---
Write-Log "Starting Create-SiteGroups script..."
if ($WhatIf) { Write-Log "*** DRY RUN MODE ***" -Level WARNING }

Write-Log "Reading CSV: $CsvPath"
$lines = Get-Content -Path $CsvPath -Encoding UTF8
$lines[0] = $lines[0] -replace '\*', ''
$raw = @($lines | ConvertFrom-Csv)
if ($raw.Count -eq 0) { Write-Log "CSV is empty." -Level ERROR; exit 1 }

$activeNetworks = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($row in $raw) {
    $disabledVal = if ($row.PSObject.Properties['disabled']) { ([string]$row.disabled).Trim() } else { '' }
    $address = if ($row.PSObject.Properties['address']) { ([string]$row.address).Trim() } else { '' }
    $netmask = if ($row.PSObject.Properties['netmask']) { ([string]$row.netmask).Trim() } else { '' }
    $site = if ($row.PSObject.Properties['EA-Site']) { ([string]$row.'EA-Site').Trim() } else { '' }

    if ($disabledVal -ine 'FALSE' -or [string]::IsNullOrWhiteSpace($address)) { continue }
    try { $prefix = Convert-NetmaskToCIDR -Netmask $netmask } catch { continue }
    
    $activeNetworks.Add([PSCustomObject]@{
        CIDR   = "$address/$prefix"
        EASite = if ([string]::IsNullOrWhiteSpace($site)) { 'Unused-EA-SITE' } else { $site }
    })
}

$allSiteGroups = @($activeNetworks | Group-Object -Property EASite)
$bySite = if ($ShowUnusedEASite) { $allSiteGroups } else { @($allSiteGroups | Where-Object { $_.Name -ne 'Unused-EA-SITE' }) }

$apiHeaders = @{ "Authorization" = $ApiKey; "Content-Type" = "application/json" }

foreach ($siteGroup in $bySite) {
    $groupName = "Site_$($siteGroup.Name)"
    $uniqueCidrs = @($siteGroup.Group | Select-Object -ExpandProperty CIDR -Unique)
    Write-Log "Processing Group: '$groupName' ($($uniqueCidrs.Count) CIDRs)"

    if ($WhatIf) { continue }

    $groupResult = Ensure-GroupExists -GroupName $groupName -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
    if (-not $groupResult.GroupID) { continue }

    $existingMemberIds = Get-ExistingGroupMembers -GroupID $groupResult.GroupID -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
    $resolvedAssetIds = [System.Collections.Generic.List[string]]::new()

    foreach ($cidr in $uniqueCidrs) {
        $assetId = Resolve-NetworkAssetId -CIDR $cidr -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
        if ($null -ne $assetId -and -not $resolvedAssetIds.Contains($assetId)) { [void]$resolvedAssetIds.Add($assetId) }
        Start-Sleep -Milliseconds $ThrottleMs
    }

    $newAssetIds = @($resolvedAssetIds | Where-Object { -not $existingMemberIds.Contains($_) })
    if ($newAssetIds.Count -gt 0) {
        $addMembersBody = @{ membersId = $newAssetIds } | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri "$BaseApiUrl/groups/custom/$($groupResult.GroupID)/members" -Method Put -Headers $apiHeaders -Body $addMembersBody
        Write-Log "Added $($newAssetIds.Count) members to '$groupName'." -Level SUCCESS
    }
}

Write-Log "Script finished."
