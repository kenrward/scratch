<#
.SYNOPSIS
    Enrolls Linux hosts from a CSV into Zero Networks, optionally pinning them
    to a deployment cluster and binding them to a Linux (SSH) profile.

.DESCRIPTION
    Reads linux-assets.csv (columns: displayName, fqdn) and creates each host
    as a manual Linux asset via POST /api/v1/assets/linux.

    Two optional values can be set at the top of this script:
        $DeploymentsClusterId  - if set, every asset created in this run is
                                 pinned to this cluster after enrollment.
        $LinuxProfileId        - if set, every asset is created using this
                                 Linux/SSH credential profile.

    Leave either blank ("") to skip that step. This run only acts on the
    configs set at the top of the script.

.NOTES
    Original: Thomas Obarowski (https://github.com/tjobarow/)
    Updated:  Ken
    Version:  2.0
#>

# ============================================================
#  CONFIG - edit these for each run
# ============================================================

$DeploymentsClusterId = "C:d:1OaoDjrW"                                      # e.g. "C:d:1OaoDjrW"  - leave "" to skip
$LinuxProfileId       = "l:c:c64c340e"                                      # e.g. "l:c:c64c340e"  - leave "" to skip

$CsvPath   = "C:\Users\12345678\Documents\Zero Network-Linux Scripts\linux-assets.csv"
$TokenPath = "C:\Users\12345678\Documents\Zero Network-Linux Scripts\token.txt"
$BaseUri   = "https://znmdlab-admin.zeronetworks.com"


# ============================================================
#  Setup
# ============================================================

$logFile = ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log"

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -UFormat "%Y-%m-%d %T"): $Message"
    Write-Host $line
    $line | Out-File -FilePath $logFile -Append
}

function Get-ErrorBody {
    # Pulls the response body out of a failed Invoke-RestMethod so we see the
    # actual API error message, not just the status code.
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }
    try {
        $stream = $ErrorRecord.Exception.Response.GetResponseStream()
        $stream.Position = 0
        return (New-Object System.IO.StreamReader($stream)).ReadToEnd()
    } catch { return "" }
}

Write-Log "Reading contents of $CsvPath..."

$token = (Get-Content -Path $TokenPath -Raw).Trim()

$headers = @{
    "Authorization" = $token
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

# Sanity-check the IDs so a swapped value fails fast instead of in the API.
if ($LinuxProfileId       -and $LinuxProfileId       -notlike "l:c:*") { Write-Log "WARN: LinuxProfileId '$LinuxProfileId' does not look like a Linux profile ID (expected 'l:c:...')." }
if ($DeploymentsClusterId -and $DeploymentsClusterId -notlike "C:d:*") { Write-Log "WARN: DeploymentsClusterId '$DeploymentsClusterId' does not look like a cluster ID (expected 'C:d:...')." }

# ============================================================
#  Create each Linux asset
# ============================================================

$createdAssetIds = @()

foreach ($row in Import-Csv -Path $CsvPath) {

    $displayName = $row.displayName.Trim()
    $fqdn        = $row.fqdn.Trim()

    if (-not $displayName) {
        Write-Log "Skipping row with empty displayName."
        continue
    }

    # If fqdn is blank, fall back to displayName.
    if (-not $fqdn) { $fqdn = $displayName }

    # Build request body.
    $body = @{
        displayName = $displayName
        fqdn        = $fqdn
    }
    if ($LinuxProfileId) { $body["profileId"] = $LinuxProfileId }

    Write-Log "POST $BaseUri/api/v1/assets/linux for $displayName ($fqdn)..."

    try {
        $response = Invoke-RestMethod `
            -Uri     "$BaseUri/api/v1/assets/linux" `
            -Method  Post `
            -Headers $headers `
            -Body    ($body | ConvertTo-Json)

        # The API may return: a bare ID string, { id: "a:l:..." },
        # { items: [ "a:l:..." ] }, or { items: [ { id: "a:l:..." } ] }.
        $assetId = $null
        if ($response -is [string]) {
            $assetId = $response
        }
        elseif ($response.id) {
            $assetId = $response.id
        }
        elseif ($response.items) {
            $first = @($response.items)[0]
            if ($first -is [string]) { $assetId = $first }
            elseif ($first.id)       { $assetId = $first.id }
        }

        if ($assetId) {
            Write-Log "Linux host created - $displayName ($fqdn) has asset ID: $assetId"
            $createdAssetIds += $assetId
        }
        else {
            Write-Log "WARN: could not find asset ID in response for $displayName. Raw response: $($response | ConvertTo-Json -Compress -Depth 5)"
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDesc = $_.Exception.Response.StatusDescription
        $errBody    = Get-ErrorBody $_
        Write-Log "Web request failed for $displayName ($fqdn): Status $statusCode - $statusDesc"
        if ($errBody) { Write-Log "Response body: $errBody" }
    }
}

# ============================================================
#  Pin all newly-created assets to the deployment cluster
# ============================================================

if (-not $DeploymentsClusterId) {
    Write-Log "DeploymentsClusterId is blank - skipping pin step."
}
elseif ($createdAssetIds.Count -eq 0) {
    Write-Log "No asset IDs were captured - nothing to pin."
}
else {
    $pinBody = @{
        assetIds             = $createdAssetIds
        deploymentsClusterId = $DeploymentsClusterId
    }

    Write-Log "Pinning $($createdAssetIds.Count) asset(s) to deployment cluster $DeploymentsClusterId..."
    Write-Log "Asset IDs to pin: $($createdAssetIds -join ', ')"

    try {
        Invoke-RestMethod `
            -Uri     "$BaseUri/api/v1/assets/actions/deployments-cluster" `
            -Method  Put `
            -Headers $headers `
            -Body    ($pinBody | ConvertTo-Json) | Out-Null

        Write-Log "Pin succeeded for cluster $DeploymentsClusterId."
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDesc = $_.Exception.Response.StatusDescription
        $errBody    = Get-ErrorBody $_
        Write-Log "Pin failed for cluster ${DeploymentsClusterId}: Status $statusCode - $statusDesc"
        if ($errBody) { Write-Log "Response body: $errBody" }
        Write-Log "Request body sent: $($pinBody | ConvertTo-Json -Compress)"
    }
}
