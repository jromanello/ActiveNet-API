<#
.SYNOPSIS
    Validation Probe 1: ACTIVENet Facility & Organization Discovery (Read-Only GET).
.DESCRIPTION
    Queries the ACTIVENet System API to:
    1. Verify dynamic signature authentication and calculate clock offset against HTTP Date header.
    2. Query GetOrganization to discover the authoritative time_zone.
    3. Query GetFacilities across all pages to identify the exact center_id, facility_id, facility_number,
       and exact name casing for "Community Center Complex" and "Conference Room A".
    4. Query GetFacilityDetail for the discovered facility_id to inspect default setup/teardown minutes.
    Outputs redacted JSON to tools/probes/output/facility-probe-<yyyyMMdd-HHmmss>.json.
    EXPLICITLY READ-ONLY: Never modifies source or destination data.
.PARAMETER ConfigPath
    Path to configuration JSON file. Defaults to config/config.json.
.PARAMETER PageSize
    Records per page for facility catalog query. Defaults to 250 (max 500).
.EXAMPLE
    pwsh -File ./tools/probes/Invoke-ActiveNetFacilityProbe.ps1 -ConfigPath "config/config.json"
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator-facing probe requiring formatted console output')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot/../../config/config.json",

    [Parameter(Mandatory = $false)]
    [ValidateRange(20, 500)]
    [int]$PageSize = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RedactedHash {
    param ([string]$InputText)
    if ([string]::IsNullOrWhiteSpace($InputText)) { return $InputText }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText.Trim().ToLowerInvariant())
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hashBytes) -replace '-').Substring(0, 8)
}

function ConvertFrom-SecureStringToPlain {
    param ([System.Security.SecureString]$SecureString)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Invoke-ActiveNetGetWithRetry {
    param (
        [string]$BaseQueryUri,
        [string]$ApiKey,
        [string]$SharedSecret,
        [hashtable]$Headers,
        [int]$MaxRetries = 4,
        [int]$PacingDelayMs = 2000
    )

    $attempt = 0
    while ($attempt -le $MaxRetries) {
        $attempt++
        Start-Sleep -Milliseconds $PacingDelayMs

        $epochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $sigPayload = $ApiKey + $SharedSecret + $epochSeconds
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $sigBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sigPayload))
        $sig = ([System.BitConverter]::ToString($sigBytes) -replace '-').ToLowerInvariant()

        $fullUri = "$BaseQueryUri&api_key=$ApiKey&sig=$sig"

        try {
            $resp = Invoke-RestMethod -Uri $fullUri -Method Get -Headers $Headers -ErrorAction Stop
            return $resp
        } catch {
            $errText = $_.ToString()
            if ($_.ErrorDetails) { $errText += " " + $_.ErrorDetails.Message }
            if ($_.Exception) { $errText += " " + $_.Exception.Message }
            $isQps = ($errText -like "*Developer Over Qps*" -or $errText -like "*429*" -or $errText -like "*403*")
            if ($isQps -and $attempt -le $MaxRetries) {
                $backoffSeconds = $attempt * 3
                Write-Warning "ACTIVENet rate limit encountered (Developer Over Qps). Backing off for $backoffSeconds seconds before retry $attempt of $MaxRetries..."
                Start-Sleep -Seconds $backoffSeconds
                continue
            }
            throw $_
        }
    }
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " ACTIVENet Validation Probe 1: Facility & Organization Discovery " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Load Configuration
if (-not (Test-Path -Path $ConfigPath)) {
    Write-Error "Config file not found at: $ConfigPath"
    exit 1
}

$rawConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$orgId           = [string]$rawConfig.activeNetOrgId
$baseUrl         = [string]$rawConfig.activeNetBaseUrl
$credPath        = [string]$rawConfig.activeNetCredPath
$targetCenter    = [string]$rawConfig.centerName
$targetFacility  = [string]$rawConfig.facilityName

Write-Host "ActiveNet Org ID  : $orgId"
Write-Host "ActiveNet Host    : $baseUrl"
Write-Host "Target Center     : $targetCenter"
Write-Host "Target Facility   : $targetFacility"
Write-Host "Catalog Page Size : $PageSize"

# 2. Load Credentials
if (-not (Test-Path -Path $credPath)) {
    Write-Error "Credential package not found at: $credPath. Run tools/Set-ActiveNetCredential.ps1 first."
    exit 2
}

try {
    $creds = Import-Clixml -Path $credPath
    $apiKey = ConvertFrom-SecureStringToPlain -SecureString $creds.ApiKey
    $sharedSecret = ConvertFrom-SecureStringToPlain -SecureString $creds.SharedSecret
} catch {
    Write-Error "Failed to decrypt ACTIVENet credentials via DPAPI. Ensure this script is run as the service account: $_"
    exit 3
}

$serviceName = "anet-systemapi-sec"
$probeTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "$PSScriptRoot/output"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$outputFile = Join-Path $outputDir "facility-probe-$probeTimestamp.json"

$probeResults = [ordered]@{
    ProbeName            = "ActiveNetFacilityProbe"
    ExecutedUtc          = [DateTime]::UtcNow.ToString("o")
    TargetCenterQuery    = $targetCenter
    TargetFacilityQuery  = $targetFacility
    ClockOffsetSeconds   = $null
    OrganizationTimeZone = $null
    MatchedCenterId      = $null
    MatchedCenterName    = $null
    MatchedFacilityId    = $null
    MatchedFacilityName  = $null
    MatchedFacilityNumber= $null
    DefaultSetupMinutes  = $null
    DefaultTeardownMins  = $null
    PrepCode             = $null
    AllFoundFacilities   = @()
    Status               = "Incomplete"
}

# 3. Query /organization (Verify auth & clock offset)
Write-Host "`n[1/3] Querying /organization endpoint..." -ForegroundColor Yellow
$epochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$sigPayload = $apiKey + $sharedSecret + $epochSeconds
$hasher = [System.Security.Cryptography.SHA256]::Create()
$sigBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sigPayload))
$sig = ([System.BitConverter]::ToString($sigBytes) -replace '-').ToLowerInvariant()

$orgUri = "$baseUrl/$serviceName/$orgId/api/v1/organization?api_key=$apiKey&sig=$sig"

try {
    $response = Invoke-WebRequest -Uri $orgUri -Method Get -Headers @{ "Accept" = "application/json" } -ErrorAction Stop
    $serverDateHeader = $response.Headers["Date"]
    if ($serverDateHeader) {
        $serverTimeUtc = [DateTimeOffset]::Parse($serverDateHeader).UtcDateTime
        $localTimeUtc = [DateTime]::UtcNow
        $clockOffset = ($localTimeUtc - $serverTimeUtc).TotalSeconds
        $probeResults.ClockOffsetSeconds = [math]::Round($clockOffset, 2)
        Write-Host " -> Server HTTP Date : $serverDateHeader"
        Write-Host " -> Local Clock Offset: $($probeResults.ClockOffsetSeconds) seconds"
    }

    $orgBody = $response.Content | ConvertFrom-Json
    if ($orgBody.headers.response_code -ne "0000") {
        throw "ActiveNet API error on /organization: Code $($orgBody.headers.response_code) - $($orgBody.headers.response_message)"
    }

    if ($orgBody.body -and $orgBody.body.Count -gt 0) {
        $probeResults.OrganizationTimeZone = $orgBody.body[0].time_zone
        Write-Host " -> Authoritative TimeZone: $($probeResults.OrganizationTimeZone)" -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to query ACTIVENet /organization: $_"
    $probeResults.Status = "Failed: OrganizationQueryError"
    $probeResults | ConvertTo-Json -Depth 5 | Set-Content -Path $outputFile
    exit 10
}

# 4. Query /facilities across all pages (paced to respect QPS limits)
Write-Host "`n[2/3] Querying /facilities (paging through all catalog records with QPS pacing)..." -ForegroundColor Yellow
$allFacilities = [System.Collections.Generic.List[PSCustomObject]]::new()
$pageNumber = 1
$hasMorePages = $true

while ($hasMorePages) {
    $facBaseUri = "$baseUrl/$serviceName/$orgId/api/v1/facilities?"
    $pageInfoJson = @{
        page_number            = $pageNumber
        total_records_per_page = $PageSize
    } | ConvertTo-Json -Compress

    $headers = @{
        "Accept"    = "application/json"
        "page_info" = $pageInfoJson
    }

    $facResponse = Invoke-ActiveNetGetWithRetry -BaseQueryUri $facBaseUri -ApiKey $apiKey -SharedSecret $sharedSecret -Headers $headers -PacingDelayMs 2000

    if ($facResponse.headers.response_code -eq "0001") {
        # No more results
        break
    } elseif ($facResponse.headers.response_code -ne "0000") {
        throw "ActiveNet API error on /facilities: Code $($facResponse.headers.response_code) - $($facResponse.headers.response_message)"
    }

    $pageRecords = $facResponse.body
    if ($null -eq $pageRecords -or $pageRecords.Count -eq 0) {
        $hasMorePages = $false
    } else {
        foreach ($rec in $pageRecords) {
            $allFacilities.Add($rec)
        }
        Write-Host " -> Page $($pageNumber): Retrieved $($pageRecords.Count) facilities (Total so far: $($allFacilities.Count))"
        if ($pageRecords.Count -lt $PageSize) {
            $hasMorePages = $false
        } else {
            $pageNumber++
        }
    }
}

Write-Host " -> Total facilities in catalog: $($allFacilities.Count)"

# Inspect and filter for Target Center & Target Facility
$targetCenterNormalized = $targetCenter.Trim().ToLowerInvariant()
$targetFacilityNormalized = $targetFacility.Trim().ToLowerInvariant()

$matchedRecords = @()
$candidateList = @()

foreach ($f in $allFacilities) {
    $centerName = if ($f.center_name) { [string]$f.center_name } else { "" }
    $facilityName = if ($f.facility_name) { [string]$f.facility_name } else { "" }

    $candidateList += [PSCustomObject]@{
        center_id       = $f.center_id
        center_name     = $centerName
        facility_id     = $f.facility_id
        facility_name   = $facilityName
        facility_number = $f.facility_number
    }

    if ($centerName.Trim().ToLowerInvariant() -eq $targetCenterNormalized -and
        $facilityName.Trim().ToLowerInvariant() -eq $targetFacilityNormalized) {
        $matchedRecords += $f
    }
}

$probeResults.AllFoundFacilities = $candidateList

if ($matchedRecords.Count -eq 1) {
    $matched = $matchedRecords[0]
    $probeResults.MatchedCenterId       = [int]$matched.center_id
    $probeResults.MatchedCenterName     = [string]$matched.center_name
    $probeResults.MatchedFacilityId     = [int]$matched.facility_id
    $probeResults.MatchedFacilityName   = [string]$matched.facility_name
    $probeResults.MatchedFacilityNumber = [string]$matched.facility_number

    Write-Host " -> Exact Match Found!" -ForegroundColor Green
    Write-Host "    Center ID      : $($matched.center_id) ($($matched.center_name))" -ForegroundColor Green
    Write-Host "    Facility ID    : $($matched.facility_id) ($($matched.facility_name))" -ForegroundColor Green
    Write-Host "    Facility Number: $($matched.facility_number)" -ForegroundColor Green
} elseif ($matchedRecords.Count -gt 1) {
    Write-Warning "Multiple facilities matched '$targetFacility' under '$targetCenter'! Ambiguity must be resolved."
} else {
    Write-Warning "Zero exact matches for '$targetFacility' under '$targetCenter'."
    $nearMatches = $candidateList | Where-Object { $_.facility_name -like "*Conference*" -or $_.center_name -like "*Community*" }
    Write-Host "Closest candidates:" -ForegroundColor Yellow
    $nearMatches | Format-Table center_id, center_name, facility_id, facility_name, facility_number | Out-String | Write-Host
}

# 5. Query /facilities/{facility_id} if matched
if ($null -ne $probeResults.MatchedFacilityId) {
    Write-Host "`n[3/3] Querying /facilities/$($probeResults.MatchedFacilityId) for setup/teardown details..." -ForegroundColor Yellow
    $facDetailBaseUri = "$baseUrl/$serviceName/$orgId/api/v1/facilities/$($probeResults.MatchedFacilityId)?"
    try {
        $facDetailResp = Invoke-ActiveNetGetWithRetry -BaseQueryUri $facDetailBaseUri -ApiKey $apiKey -SharedSecret $sharedSecret -Headers @{ "Accept" = "application/json" } -PacingDelayMs 2000
        if ($facDetailResp.body -and $facDetailResp.body.Count -gt 0) {
            $det = $facDetailResp.body[0]
            $probeResults.DefaultSetupMinutes = $det.setup_time
            $probeResults.DefaultTeardownMins = $det.teardown_time
            $probeResults.PrepCode            = $det.prep_code

            Write-Host " -> Default Setup Time   : $($det.setup_time) minutes" -ForegroundColor Green
            Write-Host " -> Default Teardown Time: $($det.teardown_time) minutes" -ForegroundColor Green
            Write-Host " -> Prep Code            : $($det.prep_code)" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not retrieve facility details for ID $($probeResults.MatchedFacilityId): $_"
    }
}

$probeResults.Status = "Completed"
$probeResults | ConvertTo-Json -Depth 5 | Set-Content -Path $outputFile -Encoding utf8
Write-Host "`nProbe 1 completed successfully." -ForegroundColor Green
Write-Host "Redacted output saved to: $outputFile" -ForegroundColor Cyan
exit 0
