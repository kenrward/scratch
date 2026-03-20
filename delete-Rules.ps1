<#
.SYNOPSIS
    Deletes Zero Networks inbound or outbound protection rules from a list of Rule IDs.

.DESCRIPTION
    Reads a file containing one Rule ID per line and deletes each corresponding
    inbound or outbound protection rule via the Zero Networks API.
    Use -Direction to specify Inbound or Outbound.
    Use -WhatIf to perform a dry run without making any changes.

.PARAMETER APIKey
    Your Zero Networks API key used for authentication.

.PARAMETER BaseURL
    The base URL for the Zero Networks API.
    Example: https://zncustlabs-admin.zeronetworks.com/api/v1/

.PARAMETER RuleFile
    Path to a plain text file containing one Rule ID per line.
    Example: C:\temp\rules_to_delete.txt

.PARAMETER Direction
    Specifies whether the rules are Inbound or Outbound. Accepted values: Inbound, Outbound.

.PARAMETER WhatIf
    Performs a dry run. Reports which rules would be deleted without making any API calls.

.EXAMPLE
    # Dry run on inbound rules
    .\Remove-ZNRules.ps1 `
        -APIKey "your-api-key" `
        -BaseURL "https://zncustlabs-admin.zeronetworks.com/api/v1/" `
        -RuleFile "C:\temp\rules.txt" `
        -Direction Inbound `
        -WhatIf

.EXAMPLE
    # Live delete of outbound rules
    .\Remove-ZNRules.ps1 `
        -APIKey "your-api-key" `
        -BaseURL "https://zncustlabs-admin.zeronetworks.com/api/v1/" `
        -RuleFile "C:\temp\rules.txt" `
        -Direction Outbound
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Zero Networks API Key")]
    [string]$APIKey,

    [Parameter(Mandatory = $true, HelpMessage = "Zero Networks API Base URL (e.g. https://tenant-admin.zeronetworks.com/api/v1/)")]
    [string]$BaseURL,

    [Parameter(Mandatory = $true, HelpMessage = "Path to text file with one Rule ID per line")]
    [string]$RuleFile,

    [Parameter(Mandatory = $true, HelpMessage = "Rule direction: Inbound or Outbound")]
    [ValidateSet("Inbound", "Outbound")]
    [string]$Direction
)

#region --- Validation ---

if (-not (Test-Path $RuleFile)) {
    Write-Error "Rule file not found: $RuleFile"
    exit 1
}

# Normalize BaseURL — ensure it ends with /
if (-not $BaseURL.EndsWith("/")) {
    $BaseURL = "$BaseURL/"
}

# Set path segment based on direction
$directionSegment = $Direction.ToLower()

# Read rule IDs, skip blank lines and comment lines
$RuleIDs = Get-Content $RuleFile | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

if ($RuleIDs.Count -eq 0) {
    Write-Warning "No Rule IDs found in $RuleFile. Exiting."
    exit 0
}

#endregion

#region --- Determine WhatIf Mode ---

$isDryRun = $WhatIfPreference.IsPresent

#endregion

#region --- Headers ---

$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization", $APIKey)
$znHeaders.Add("content-type", "application/json")

#endregion

#region --- Run Summary ---

$timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$reportLines = [System.Collections.Generic.List[string]]::new()

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Zero Networks — $Direction Rule Deletion" -ForegroundColor Cyan
if ($isDryRun) {
    Write-Host "  MODE: DRY RUN (WhatIf) — No changes will be made" -ForegroundColor Yellow
} else {
    Write-Host "  MODE: LIVE — Rules will be permanently deleted" -ForegroundColor Red
}
Write-Host "  Timestamp : $timestamp"
Write-Host "  Base URL  : $BaseURL"
Write-Host "  Direction : $Direction"
Write-Host "  Rule File : $RuleFile"
Write-Host "  Rules     : $($RuleIDs.Count) found"
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$reportLines.Add("Zero Networks $Direction Rule Deletion Report")
$reportLines.Add("==========================================")
$reportLines.Add("Timestamp : $timestamp")
$reportLines.Add("Base URL  : $BaseURL")
$reportLines.Add("Direction : $Direction")
$reportLines.Add("Rule File : $RuleFile")
$reportLines.Add("Mode      : $(if ($isDryRun) { 'DRY RUN (WhatIf)' } else { 'LIVE' })")
$reportLines.Add("Rules     : $($RuleIDs.Count) found")
$reportLines.Add("")
$reportLines.Add("Rule ID`t`t`t`t`t`tAction`t`tResult")
$reportLines.Add("-" * 80)

#endregion

#region --- Process Rules ---

$successCount = 0
$skipCount    = 0
$failCount    = 0
$rejectCount  = 0

foreach ($RuleID in $RuleIDs) {

    $endpoint = "${BaseURL}protection/rules/${directionSegment}/${RuleID}"

    if ($isDryRun) {
        Write-Host "  [WHATIF] Would DELETE: $RuleID" -ForegroundColor Yellow
        Write-Host "           URL: $endpoint" -ForegroundColor DarkGray
        Write-Host "           (If proposed state) Would PUT: ${BaseURL}protection/rules/${directionSegment}/review/reject-delete/${RuleID}" -ForegroundColor DarkGray
        $reportLines.Add("$RuleID`tWOULD DELETE (or REJECT-DELETE if proposed)`t(dry run — no change made)")
        $skipCount++
    }
    else {
        try {
            $response = Invoke-RestMethod `
                -Uri        $endpoint `
                -Method     DELETE `
                -Headers    $znHeaders `
                -ErrorAction Stop

            Write-Host "  [SUCCESS] Deleted: $RuleID" -ForegroundColor Green
            $reportLines.Add("$RuleID`tDELETED`t`tHTTP 200 OK")
            $successCount++
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__

            if ($statusCode -eq 400) {
                # Rule is in a proposed/review state — escalate to reject-delete
                Write-Host "  [PROPOSED] Rule in review state, attempting reject-delete: $RuleID" -ForegroundColor Magenta

                $rejectEndpoint = "${BaseURL}protection/rules/${directionSegment}/review/reject-delete/${RuleID}"
                $rejectPayload  = '{"review":{"reason":7,"details":"bulk reject script"}}'

                try {
                    $rejectResponse = Invoke-RestMethod `
                        -Uri         $rejectEndpoint `
                        -Method      PUT `
                        -Headers     $znHeaders `
                        -Body        $rejectPayload `
                        -ErrorAction Stop

                    Write-Host "  [SUCCESS] Reject-deleted: $RuleID" -ForegroundColor Green
                    $reportLines.Add("$RuleID`tREJECT-DELETED`tProposed rule — PUT reject-delete succeeded")
                    $rejectCount++
                }
                catch {
                    $rejectStatus = $_.Exception.Response.StatusCode.value__
                    $rejectErr    = $_.Exception.Message

                    Write-Host "  [FAILED]  Reject-delete failed for: $RuleID" -ForegroundColor Red
                    Write-Host "            Status : $rejectStatus" -ForegroundColor Red
                    Write-Host "            Error  : $rejectErr" -ForegroundColor DarkRed

                    $reportLines.Add("$RuleID`tFAILED`t`tHTTP 400 on DELETE, then HTTP $rejectStatus on reject-delete — $rejectErr")
                    $failCount++
                }
            }
            else {
                $errMsg = $_.Exception.Message

                Write-Host "  [FAILED]  Rule ID : $RuleID" -ForegroundColor Red
                Write-Host "            Status  : $statusCode" -ForegroundColor Red
                Write-Host "            Error   : $errMsg" -ForegroundColor DarkRed

                $reportLines.Add("$RuleID`tFAILED`t`tHTTP $statusCode — $errMsg")
                $failCount++
            }
        }
    }
}

#endregion

#region --- Summary Footer ---

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
if ($isDryRun) {
    Write-Host "  DRY RUN COMPLETE" -ForegroundColor Yellow
    Write-Host "  Rules that would be deleted : $skipCount" -ForegroundColor Yellow
} else {
    Write-Host "  RUN COMPLETE" -ForegroundColor Cyan
    Write-Host "  Successfully deleted        : $successCount" -ForegroundColor Green
    Write-Host "  Reject-deleted (proposed)   : $rejectCount"  -ForegroundColor Magenta
    Write-Host "  Failed                      : $failCount"    -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
}
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$reportLines.Add("")
$reportLines.Add("==========================================")
if ($isDryRun) {
    $reportLines.Add("DRY RUN COMPLETE — No changes were made.")
    $reportLines.Add("Rules that would be deleted : $skipCount")
} else {
    $reportLines.Add("RUN COMPLETE")
    $reportLines.Add("Successfully deleted      : $successCount")
    $reportLines.Add("Reject-deleted (proposed) : $rejectCount")
    $reportLines.Add("Failed                    : $failCount")
}
$reportLines.Add("Generated : $timestamp")

#endregion

#region --- Save Report ---

$reportPath = Join-Path (Split-Path $RuleFile) ("ZN_DeleteRules_Report_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")

try {
    $reportLines | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "  Report saved to: $reportPath" -ForegroundColor Cyan
} catch {
    Write-Warning "Could not save report to $reportPath — $_"
}

#endregion
