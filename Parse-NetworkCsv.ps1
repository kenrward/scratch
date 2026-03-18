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
    .\Parse-NetworkCsv.ps1 -CsvPath './dl-nets-export-20250126.csv' `
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
    param(
        [string]$GroupName,
        [string]$BaseApiUrl,
        [hashtable]$Headers
    )
 
    $result = @{ GroupID = $null; NewlyCreated = $false }
 
    Write-Log "Checking if group '$GroupName' exists..."
    $filterValue = '[{"id":"name","includeValues":["' + $GroupName + '"],"excludeValues":[]}]'
    $encodedFilter = [System.Uri]::EscapeDataString($filterValue)
    $checkGroupUri = "$BaseApiUrl/groups/custom?_limit=1&_filters=$encodedFilter"
 
    $existingGroupResponse = Invoke-RestMethod -Uri $checkGroupUri -Method Get -Headers $Headers
 
    if ($existingGroupResponse.items -and @($existingGroupResponse.items).Count -gt 0) {
        $result.GroupID = @($existingGroupResponse.items)[0].id
        Write-Log "Group '$GroupName' found with ID: $($result.GroupID)"
        return $result
    }
 
    Write-Log "Group '$GroupName' not found. Creating..."
    $createGroupUri = "$BaseApiUrl/groups/custom"
    $createGroupBody = @{
        name        = $GroupName
        description = "Site group for $GroupName (auto-created by Create-SiteGroups script)"
        membersId   = @()
    } | ConvertTo-Json -Depth 5
 
    $newGroupResponse = Invoke-RestMethod -Uri $createGroupUri -Method Post -Headers $Headers -Body $createGroupBody
 
    if ($newGroupResponse.entity -and $newGroupResponse.entity.id) {
        $result.GroupID = $newGroupResponse.entity.id
        $result.NewlyCreated = $true
        Write-Log "Group '$GroupName' created with ID: $($result.GroupID)" -Level SUCCESS
    }
    else {
        Write-Log "Failed to create group '$GroupName' or retrieve its ID from response." -Level ERROR
        Write-Log "API Response: $(ConvertTo-Json $newGroupResponse -Depth 5)"
    }
 
    return $result
}
 
function Verify-GroupExists {
    param(
        [string]$GroupName,
        [string]$GroupID,
        [string]$BaseApiUrl,
        [hashtable]$Headers,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 3
    )
 
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Log "Verifying group '$GroupName' (ID: $GroupID), attempt $attempt of $MaxRetries..."
        try {
            $verifyUri = "$BaseApiUrl/groups/custom/$GroupID"
            $response = Invoke-RestMethod -Uri $verifyUri -Method Get -Headers $Headers
 
            if ($response.entity -and $response.entity.id -eq $GroupID) {
                Write-Log "Group '$GroupName' (ID: $GroupID) verified." -Level SUCCESS
                return $true
            }
            else {
                Write-Log "Verification response structure unexpected for '$GroupName'." -Level WARNING
            }
        }
        catch {
            Write-Log "Verification attempt $attempt failed: $($_.Exception.Message)" -Level WARNING
        }
 
        if ($attempt -lt $MaxRetries) {
            Write-Log "Waiting $RetryDelaySeconds seconds before retry..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
 
    Write-Log "Failed to verify group '$GroupName' (ID: $GroupID) after $MaxRetries attempts." -Level ERROR
    return $false
}
 
function Resolve-NetworkAssetId {
    <#
    .SYNOPSIS
        Resolves a CIDR (e.g., 10.20.51.0/24) to a Zero Networks asset ID
        using the group member-candidates endpoint. Retries on transient
        errors (429, 502, 503, 504) with exponential backoff.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,
 
        [Parameter(Mandatory)]
        [string]$BaseApiUrl,
 
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
 
    $encodedCIDR  = [System.Uri]::EscapeDataString($CIDR)
    $candidateUri = "$BaseApiUrl/groups/custom/member-candidates?_search=$encodedCIDR&_limit=100&_offset=0"
 
    $maxRetries  = 4
    $retryDelay  = 2   # seconds; doubles on each retry (2 -> 4 -> 8)
 
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $results = Invoke-RestMethod -Uri $candidateUri -Method Get -Headers $Headers
 
            if ($results.items -and @($results.items).Count -gt 0) {
                # Prefer an exact name match to avoid partial-match false positives
                foreach ($item in @($results.items)) {
                    $itemName = if ($null -ne $item.name) { $item.name } else { '' }
                    if ($itemName -eq $CIDR) {
                        return $item.id
                    }
                }
                # Fall back to first result if no exact match
                Write-Verbose "  No exact name match for '$CIDR'; using first candidate: $(@($results.items)[0].id)"
                return @($results.items)[0].id
            }
            else {
                Write-Log "  No member-candidate match for CIDR '$CIDR'." -Level WARNING
                return $null
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -in @(429, 502, 503, 504) -and $attempt -lt $maxRetries) {
                Write-Log "  Transient $statusCode for '$CIDR'. Retry $attempt/$maxRetries in ${retryDelay}s..." -Level WARNING
                Start-Sleep -Seconds $retryDelay
                $retryDelay *= 2   # exponential backoff: 2s -> 4s -> 8s
            }
            else {
                Write-Log "  Failed to resolve asset ID for CIDR '$CIDR': $($_.Exception.Message)" -Level ERROR
                return $null
            }
        }
    }
 
    Write-Log "  Gave up resolving '$CIDR' after $maxRetries attempts." -Level ERROR
    return $null
}
 
# ============================================================
# MAIN SCRIPT
# ============================================================
 
Write-Log "Starting Create-SiteGroups script..."
if ($WhatIf) {
    Write-Log "*** DRY RUN MODE -- no API calls will be made ***" -Level WARNING
}
 
# --- 1. Read and sanitize CSV ---
Write-Log "Reading CSV: $CsvPath"
$lines = Get-Content -Path $CsvPath -Encoding UTF8
$lines[0] = $lines[0] -replace '\*', ''
$raw = @($lines | ConvertFrom-Csv)
 
if ($raw.Count -eq 0) {
    Write-Log "CSV is empty or could not be parsed." -Level ERROR
    exit 1
}
 
Write-Log "Loaded $($raw.Count) rows from CSV"
 
# --- 2. Filter active networks and convert to CIDR ---
$activeNetworks = [System.Collections.Generic.List[PSCustomObject]]::new()
 
foreach ($row in $raw) {
    # Safe property access: PSObject.Properties check guards against missing columns (StrictMode);
    # [string] cast guards against null values even when the column exists.
    $disabledVal = if ($row.PSObject.Properties['disabled'])    { ([string]$row.disabled).Trim() }    else { '' }
    $address     = if ($row.PSObject.Properties['address'])     { ([string]$row.address).Trim() }     else { '' }
    $netmask     = if ($row.PSObject.Properties['netmask'])     { ([string]$row.netmask).Trim() }     else { '' }
    $domain      = if ($row.PSObject.Properties['domain_name']) { ([string]$row.domain_name).Trim() } else { '' }
    $site        = if ($row.PSObject.Properties['EA-Site'])     { ([string]$row.'EA-Site').Trim() }   else { '' }
 
    # Keep only explicitly-enabled networks (disabled = FALSE)
    if ($disabledVal -ine 'FALSE') { continue }
 
    if ([string]::IsNullOrWhiteSpace($address) -or [string]::IsNullOrWhiteSpace($netmask)) {
        Write-Verbose "Skipping row with empty address or netmask"
        continue
    }
 
    try {
        $prefix = Convert-NetmaskToCIDR -Netmask $netmask
    }
    catch {
        Write-Log "Skipping '$address': $_" -Level WARNING
        continue
    }
 
    $cidr = "$address/$prefix"
 
    if ([string]::IsNullOrWhiteSpace($site)) {
        $site = 'Unused-EA-SITE'
    }
 
    $activeNetworks.Add([PSCustomObject]@{
        Address    = $address
        CIDR       = $cidr
        DomainName = $domain
        EASite     = $site
    })
}
 
Write-Log "Active networks after filtering: $($activeNetworks.Count)"
 
# --- 3. Group by EA-Site ---
$allSiteGroups = @($activeNetworks | Group-Object -Property EASite | Sort-Object Name)
 
if (-not $ShowUnusedEASite) {
    $unusedGroups = @($allSiteGroups | Where-Object { $_.Name -eq 'Unused-EA-SITE' })
    if ($unusedGroups.Count -gt 0) {
        $suppressedCount = 0
        foreach ($ug in $unusedGroups) { $suppressedCount += $ug.Count }
        Write-Log "Suppressing $suppressedCount networks with no EA-Site. Use -ShowUnusedEASite to include." -Level WARNING
    }
    $bySite = @($allSiteGroups | Where-Object { $_.Name -ne 'Unused-EA-SITE' })
}
else {
    $bySite = $allSiteGroups
}
 
Write-Log "EA-Site groups to process: $($bySite.Count)"
 
# --- 4. API setup ---
$apiHeaders = @{
    "Authorization" = $ApiKey
    "Content-Type"  = "application/json"
}
 
# --- 5. Process each EA-Site group ---
foreach ($siteGroup in $bySite) {
    $eaSiteName  = $siteGroup.Name
    $groupName   = "Site_$eaSiteName"
    $networks    = @($siteGroup.Group | Sort-Object CIDR)
    $uniqueCidrs = @($networks | Select-Object -ExpandProperty CIDR -Unique)
 
    Write-Log "Processing EA-Site: '$eaSiteName' -> Group: '$groupName' ($($uniqueCidrs.Count) unique CIDRs)"
 
    if ($WhatIf) {
        Write-Log "[DRY RUN] Would create/ensure group '$groupName' and resolve + add $($uniqueCidrs.Count) CIDRs:"
        foreach ($c in $uniqueCidrs) {
            Write-Log "  [DRY RUN]   $c"
        }
        Write-Host ""
        continue
    }
 
    # (a) Ensure group exists
    $targetGroupID = $null
    try {
        $groupResult = Ensure-GroupExists -GroupName $groupName -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
 
        if (-not $groupResult.GroupID) {
            Write-Log "Could not obtain Group ID for '$groupName'. Skipping." -Level ERROR
            continue
        }
 
        $targetGroupID = $groupResult.GroupID
 
        if ($groupResult.NewlyCreated) {
            $verified = Verify-GroupExists -GroupName $groupName -GroupID $targetGroupID `
                -BaseApiUrl $BaseApiUrl -Headers $apiHeaders -MaxRetries 3 -RetryDelaySeconds 3
 
            if (-not $verified) {
                Write-Log "Skipping member addition for '$groupName' -- verification failed." -Level ERROR
                continue
            }
        }
    }
    catch {
        Write-Log "Exception during group check/creation for '$groupName': $($_.Exception.Message)" -Level ERROR
        if ($_.ErrorDetails) {
            Write-Log "API Response: $($_.ErrorDetails.Message)"
        }
        continue
    }
 
    # (b) Resolve each CIDR to a ZN asset ID via /groups/custom/member-candidates
    $resolvedAssetIds = [System.Collections.Generic.List[string]]::new()
    $failedResolutions = 0
 
    Write-Log "Resolving $($uniqueCidrs.Count) CIDRs to asset IDs for group '$groupName'..."
 
    foreach ($cidr in $uniqueCidrs) {
        Write-Verbose "  Resolving: $cidr"
 
        $assetId = Resolve-NetworkAssetId -CIDR $cidr -BaseApiUrl $BaseApiUrl -Headers $apiHeaders
 
        # Throttle to avoid overwhelming the API (configurable via -ThrottleMs)
        Start-Sleep -Milliseconds $ThrottleMs
 
        if ($null -ne $assetId -and $assetId -ne '') {
            if (-not $resolvedAssetIds.Contains($assetId)) {
                $resolvedAssetIds.Add($assetId)
                Write-Verbose "  Resolved: $cidr -> $assetId"
            }
            else {
                Write-Verbose "  Duplicate asset ID for $cidr (already added)"
            }
        }
        else {
            $failedResolutions++
        }
    }
 
    Write-Log "Resolved $($resolvedAssetIds.Count) of $($uniqueCidrs.Count) CIDRs ($failedResolutions failed)"
 
    # (c) Add resolved asset IDs as members to the group
    if ($resolvedAssetIds.Count -gt 0) {
        Write-Log "Adding $($resolvedAssetIds.Count) members to group '$groupName' (ID: $targetGroupID)..."
        try {
            $addMembersUri  = "$BaseApiUrl/groups/custom/$targetGroupID/members"
            $addMembersBody = @{
                membersId = $resolvedAssetIds.ToArray()
            } | ConvertTo-Json -Depth 5
 
            Invoke-RestMethod -Uri $addMembersUri -Method Put -Headers $apiHeaders -Body $addMembersBody
            Write-Log "Successfully added $($resolvedAssetIds.Count) members to group '$groupName'." -Level SUCCESS
        }
        catch {
            Write-Log "Exception adding members to '$groupName' (ID: $targetGroupID): $($_.Exception.Message)" -Level ERROR
            Write-Log "URI: $addMembersUri"
            Write-Log "Body: $addMembersBody"
            if ($_.ErrorDetails) {
                Write-Log "API Response: $($_.ErrorDetails.Message)"
            }
        }
    }
    else {
        Write-Log "No asset IDs resolved for group '$groupName'. No members added." -Level WARNING
    }
 
    Write-Log "Finished processing group '$groupName'."
    Write-Host ""
}
 
Write-Log "Script finished."