$BaseApiUrl = "YOUR_API_URL" # e.g. https://portal.zeronetworks.com/api/v1
$ApiKey     = "YOUR_API_KEY"
$TestCIDR   = "10.20.51.0/24" # Use a CIDR you know exists

$Headers = @{
    "Authorization" = $ApiKey
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

$EncodedCIDR  = [System.Uri]::EscapeDataString($TestCIDR)
$Uri = "$BaseApiUrl/groups/custom/member-candidates?_search=$EncodedCIDR&_limit=10&_offset=0"

Write-Host "--- Starting API Diagnostic for CIDR: $TestCIDR ---" -ForegroundColor Cyan
Write-Host "Target URI: $Uri"

try {
    # Using Invoke-WebRequest to see the raw content before PowerShell tries to convert to an object
    $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop
    
    Write-Host "Status Code: $($response.StatusCode) ($($response.StatusDescription))" -ForegroundColor Green
    Write-Host "Raw Content Preview (First 500 chars):" -ForegroundColor Yellow
    Write-Host ($response.Content.Substring(0, [Math]::Min(500, $response.Content.Length)))
    
    # Attempt to manually convert to JSON to see where it breaks
    $json = $response.Content | ConvertFrom-Json
    Write-Host "`nSuccessfully parsed JSON. Items found: $($json.items.Count)" -ForegroundColor Green
    
    if ($json.items.Count -gt 0) {
        $json.items | Select-Object id, name, entityType | Format-Table -AutoSize
    }
}
catch {
    Write-Host "--- ERROR DETECTED ---" -ForegroundColor Red
    Write-Host "Exception Message: $($_.Exception.Message)"
    
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd()
        Write-Host "Error Body from Server: $body" -ForegroundColor Red
        Write-Host "Headers from Server:"
        $_.Exception.Response.Headers | Out-String
    }
}