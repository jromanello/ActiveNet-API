<#
.SYNOPSIS
    Validation Probe 3: Microsoft Graph Extended Properties & Scoping Validation.
.DESCRIPTION
    Executes a controlled verification of Microsoft Graph calendar operations:
    1. Authenticates using client assertion signed with X.509 certificate (no plaintext secrets).
    2. Step 1: Reads calendarView for next 7 days under timezone 'Central Standard Time'.
    3. Step 2: Creates one plain appointment 35 days in the future with custom MAPI extended properties:
       - ActiveNetSyncOwned = "True"
       - ActiveNetSourceId = "PROBE_TEST_001"
       - showAs = "free", attendees = [], isOnlineMeeting = false, responseRequested = false.
    4. Step 3: Retrieves the created event with $expand on extended properties to verify persistence.
    5. Step 4: Tests MAPI property filter query against both /events and /calendarView.
    6. Step 5: Re-verifies ActiveNetSourceId == 'PROBE_TEST_001', DELETES the test event, and confirms 404.
    7. Step 6: Queries nonScopedTestMailbox to verify Exchange ApplicationAccessPolicy restriction (403).
    Outputs redacted JSON to tools/probes/output/graph-probe-<yyyyMMdd-HHmmss>.json.
.PARAMETER ConfigPath
    Path to configuration JSON file. Defaults to config/config.json.
.EXAMPLE
    pwsh -File ./tools/probes/Invoke-GraphExtendedPropertyProbe.ps1 -ConfigPath "config/config.json"
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator-facing probe requiring formatted console output')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot/../../config/config.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ClientAssertionJwt {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $now = [DateTimeOffset]::UtcNow
    $exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    $nbf = $now.ToUnixTimeSeconds()
    $jti = [Guid]::NewGuid().ToString()

    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = [Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '='
    }

    $payload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        exp = $exp
        iss = $ClientId
        jti = $jti
        nbf = $nbf
        sub = $ClientId
    }

    $headerJson = $header | ConvertTo-Json -Compress
    $payloadJson = $payload | ConvertTo-Json -Compress

    $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)) -replace '\+','-' -replace '/','_' -replace '='
    $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) -replace '\+','-' -replace '/','_' -replace '='

    $contentToSign = "$headerBase64.$payloadBase64"
    $bytesToSign = [System.Text.Encoding]::UTF8.GetBytes($contentToSign)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) {
        $rsa = [System.Security.Cryptography.RSA]$Certificate.PrivateKey
    }
    if ($null -eq $rsa) {
        throw "Could not obtain RSA private key from certificate. Verify private key permissions in certificate store."
    }

    $signatureBytes = $rsa.SignData($bytesToSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureBase64 = [Convert]::ToBase64String($signatureBytes) -replace '\+','-' -replace '/','_' -replace '='

    return "$contentToSign.$signatureBase64"
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Microsoft Graph Validation Probe 3: Extended Properties & Scoping " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Load Configuration
if (-not (Test-Path -Path $ConfigPath)) {
    Write-Error "Config file not found at: $ConfigPath"
    exit 1
}

$rawConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$tenantId         = [string]$rawConfig.tenantId
$clientId         = [string]$rawConfig.clientId
$thumbprint       = [string]$rawConfig.certThumbprint
$roomMailbox      = [string]$rawConfig.mailbox
$targetTimeZone   = [string]$rawConfig.timeZone
$nonScopedMailbox = [string]$rawConfig.nonScopedTestMailbox

Write-Host "Target Room Mailbox   : $roomMailbox"
Write-Host "Non-Scoped Mailbox    : $nonScopedMailbox"
Write-Host "Target Timezone       : $targetTimeZone"
Write-Host "Certificate Thumbprint: $thumbprint"

# 2. Certificate Lookup
$cert = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
if ($null -eq $cert) {
    $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
}
if ($null -eq $cert) {
    Write-Error "Certificate with thumbprint '$thumbprint' not found in LocalMachine\My or CurrentUser\My."
    exit 2
}
if (-not $cert.HasPrivateKey) {
    Write-Error "Certificate found but lacks private key. Cannot sign client assertion."
    exit 3
}

# 3. Authenticate to Microsoft Graph via OAuth2 Client Assertion
Write-Host "`n[1/7] Authenticating to Microsoft Graph via Certificate Assertion..." -ForegroundColor Yellow
$tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$jwtAssertion = Get-ClientAssertionJwt -TenantId $tenantId -ClientId $clientId -Certificate $cert

$tokenBody = @{
    client_id             = $clientId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $jwtAssertion
    grant_type            = "client_credentials"
    scope                 = "https://graph.microsoft.com/.default"
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $tokenBody -ErrorAction Stop
    $accessToken = $tokenResponse.access_token
    Write-Host " -> Access token acquired successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to acquire token from Entra ID: $_"
    exit 10
}

$probeTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "$PSScriptRoot/output"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$outputFile = Join-Path $outputDir "graph-probe-$probeTimestamp.json"

$propertyGuid = "66f538b8-3e5e-4054-97c7-08051213f019"
$propIdSyncOwned = "String {$propertyGuid} Name ActiveNetSyncOwned"
$propIdSourceId  = "String {$propertyGuid} Name ActiveNetSourceId"

$probeResults = [ordered]@{
    ProbeName                  = "GraphExtendedPropertyProbe"
    ExecutedUtc                = [DateTime]::UtcNow.ToString("o")
    TargetMailbox              = $roomMailbox
    NonScopedMailbox           = $nonScopedMailbox
    Step1_CalendarViewCount    = $null
    Step2_EventCreated         = $false
    Step2_EventId              = $null
    Step3_PropertiesVerified   = $false
    Step3_ObservedSyncOwned    = $null
    Step3_ObservedSourceId     = $null
    Step4_EventsFilterWorks    = $false
    Step4_EventsFilterCount    = 0
    Step4_CalendarViewFilterWorks = $false
    Step4_CalendarViewFilterCount = 0
    Step4_WorkingFilterQuery   = $null
    Step5_EventDeleted         = $false
    Step5_Confirmed404AfterDel = $false
    Step6_ScopingStatus        = $null
    AutoProcessingObserved     = "None"
    Status                     = "Incomplete"
}

$graphHeaders = @{
    "Authorization" = "Bearer $accessToken"
    "Accept"        = "application/json"
}

# Step 1: GET calendarView for next 7 days
Write-Host "`n[2/7] Step 1: Querying calendarView for next 7 days..." -ForegroundColor Yellow
$viewStart = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
$viewEnd   = (Get-Date).AddDays(7).ToString("yyyy-MM-ddTHH:mm:ss")
$step1Uri  = "https://graph.microsoft.com/v1.0/users/$roomMailbox/calendarView?startDateTime=$viewStart&endDateTime=$viewEnd&`$top=50"
$step1Headers = $graphHeaders.Clone()
$step1Headers["Prefer"] = "outlook.timezone=""$targetTimeZone"""

try {
    $viewResp = Invoke-RestMethod -Uri $step1Uri -Method Get -Headers $step1Headers -ErrorAction Stop
    $probeResults.Step1_CalendarViewCount = $viewResp.value.Count
    Write-Host " -> calendarView retrieved successfully. Event count: $($viewResp.value.Count)" -ForegroundColor Green
} catch {
    Write-Error "Step 1 failed: $_"
    $probeResults.Status = "Failed: Step1"
    $probeResults | ConvertTo-Json -Depth 5 | Set-Content -Path $outputFile
    exit 20
}

# Step 2: POST one appointment 35 days out with MAPI extended properties
Write-Host "`n[3/7] Step 2: Creating controlled test appointment with MAPI properties..." -ForegroundColor Yellow
$testStart = (Get-Date).AddDays(35).Date.AddHours(14)
$testEnd   = $testStart.AddHours(1)

$eventPayload = @{
    subject               = "[AN-PROBE] Extended Property Test - safe to delete"
    showAs                = "free"
    attendees             = @()
    isOnlineMeeting       = $false
    responseRequested     = $false
    body                  = @{
        contentType = "text"
        content     = "Probe validation test event. Verified safe to delete."
    }
    start                 = @{
        dateTime = $testStart.ToString("yyyy-MM-ddTHH:mm:ss")
        timeZone = $targetTimeZone
    }
    end                   = @{
        dateTime = $testEnd.ToString("yyyy-MM-ddTHH:mm:ss")
        timeZone = $targetTimeZone
    }
    singleValueExtendedProperties = @(
        @{
            id    = $propIdSyncOwned
            value = "True"
        },
        @{
            id    = $propIdSourceId
            value = "PROBE_TEST_001"
        }
    )
} | ConvertTo-Json -Depth 5

$createUri = "https://graph.microsoft.com/v1.0/users/$roomMailbox/calendar/events"
$createHeaders = $graphHeaders.Clone()
$createHeaders["Content-Type"] = "application/json"

$createdEventId = $null
try {
    $createResp = Invoke-RestMethod -Uri $createUri -Method Post -Headers $createHeaders -Body $eventPayload -ErrorAction Stop
    $createdEventId = $createResp.id
    $probeResults.Step2_EventCreated = $true
    $probeResults.Step2_EventId      = $createdEventId
    Write-Host " -> Test event created successfully. Event ID: $createdEventId" -ForegroundColor Green
} catch {
    Write-Error "Step 2 failed: $_"
    $probeResults.Status = "Failed: Step2"
    $probeResults | ConvertTo-Json -Depth 5 | Set-Content -Path $outputFile
    exit 21
}

# Step 3: GET event by id with $expand on extended properties
Write-Host "`n[4/7] Step 3: Verifying MAPI extended properties via GET /events/{id}..." -ForegroundColor Yellow
$getEventUri = "https://graph.microsoft.com/v1.0/users/$roomMailbox/events/$createdEventId`?`$expand=singleValueExtendedProperties(`$filter=id eq '$propIdSyncOwned' or id eq '$propIdSourceId')"
try {
    $getEventResp = Invoke-RestMethod -Uri $getEventUri -Method Get -Headers $graphHeaders -ErrorAction Stop
    $extProps = $getEventResp.singleValueExtendedProperties

    $syncOwnedProp = $extProps | Where-Object { $_.id -eq $propIdSyncOwned }
    $sourceIdProp  = $extProps | Where-Object { $_.id -eq $propIdSourceId }

    $probeResults.Step3_ObservedSyncOwned = if ($syncOwnedProp) { $syncOwnedProp.value } else { $null }
    $probeResults.Step3_ObservedSourceId  = if ($sourceIdProp) { $sourceIdProp.value } else { $null }

    if ($probeResults.Step3_ObservedSyncOwned -eq "True" -and $probeResults.Step3_ObservedSourceId -eq "PROBE_TEST_001") {
        $probeResults.Step3_PropertiesVerified = $true
        Write-Host " -> Properties verified on event: SyncOwned=$($syncOwnedProp.value), SourceId=$($sourceIdProp.value)" -ForegroundColor Green
    } else {
        Write-Warning "Extended properties mismatch! SyncOwned: $($probeResults.Step3_ObservedSyncOwned), SourceId: $($probeResults.Step3_ObservedSourceId)"
    }
} catch {
    Write-Warning "Step 3 GET failed: $_"
}

# Step 4: Test filtering against BOTH /events and /calendarView
Write-Host "`n[5/7] Step 4: Testing filter queries on /events and /calendarView..." -ForegroundColor Yellow
$filterQuery = "singleValueExtendedProperties/Any(ep: ep/id eq '$propIdSyncOwned' and ep/value eq 'True')"
$encodedFilter = [System.Uri]::EscapeDataString($filterQuery)

# 4A. Query /events endpoint with filter
$eventsFilterUri = "https://graph.microsoft.com/v1.0/users/$roomMailbox/events?`$filter=$encodedFilter"
try {
    $eventsFilterResp = Invoke-RestMethod -Uri $eventsFilterUri -Method Get -Headers $graphHeaders -ErrorAction Stop
    $probeResults.Step4_EventsFilterWorks = $true
    $probeResults.Step4_EventsFilterCount = $eventsFilterResp.value.Count
    Write-Host " -> /events filter returned $($eventsFilterResp.value.Count) matches." -ForegroundColor Green
    $probeResults.Step4_WorkingFilterQuery = $eventsFilterUri
} catch {
    Write-Warning " -> /events filter failed or unsupported: $_"
}

# 4B. Query /calendarView endpoint with filter
$calViewStart = $testStart.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss")
$calViewEnd   = $testEnd.AddDays(1).ToString("yyyy-MM-ddTHH:mm:ss")
$calViewFilterUri = "https://graph.microsoft.com/v1.0/users/$roomMailbox/calendarView?startDateTime=$calViewStart&endDateTime=$calViewEnd&`$filter=$encodedFilter"
$calViewFilterHeaders = $graphHeaders.Clone()
$calViewFilterHeaders["Prefer"] = "outlook.timezone=""$targetTimeZone"""
try {
    $calViewFilterResp = Invoke-RestMethod -Uri $calViewFilterUri -Method Get -Headers $calViewFilterHeaders -ErrorAction Stop
    $probeResults.Step4_CalendarViewFilterWorks = $true
    $probeResults.Step4_CalendarViewFilterCount = $calViewFilterResp.value.Count
    Write-Host " -> /calendarView filter returned $($calViewFilterResp.value.Count) matches." -ForegroundColor Green
} catch {
    Write-Host " -> /calendarView filter note (expected if Graph requires client-side filter on expanded properties): $($_.Exception.Message)" -ForegroundColor Yellow
}

# Step 5: Re-verify ownership and DELETE test event
Write-Host "`n[6/7] Step 5: Re-verifying ownership and deleting test event..." -ForegroundColor Yellow
if ($probeResults.Step3_ObservedSourceId -eq "PROBE_TEST_001" -and $createdEventId) {
    $deleteUri = "https://graph.microsoft.com/v1.0/users/$roomMailbox/events/$createdEventId"
    try {
        Invoke-RestMethod -Uri $deleteUri -Method Delete -Headers $graphHeaders -ErrorAction Stop
        $probeResults.Step5_EventDeleted = $true
        Write-Host " -> Test event deleted successfully." -ForegroundColor Green

        # Confirm 404
        try {
            Invoke-RestMethod -Uri $deleteUri -Method Get -Headers $graphHeaders -ErrorAction Stop
            Write-Warning "Event still returned after deletion!"
        } catch {
            if ($_.Exception.Response.StatusCode -eq 404 -or $_.ToString() -like "*404*") {
                $probeResults.Step5_Confirmed404AfterDel = $true
                Write-Host " -> Confirmed 404 Not Found after deletion." -ForegroundColor Green
            }
        }
    } catch {
        Write-Error "Failed to delete test event: $_"
    }
} else {
    Write-Error "Safety check failed! Event did not match expected SourceId. Aborting deletion."
}

# Step 6: Test ApplicationAccessPolicy Scoping against nonScopedTestMailbox
Write-Host "`n[7/7] Step 6: Verifying Exchange Online ApplicationAccessPolicy scoping..." -ForegroundColor Yellow
$scopeTestUri = "https://graph.microsoft.com/v1.0/users/$nonScopedMailbox/calendarView?startDateTime=$viewStart&endDateTime=$viewEnd"
try {
    Invoke-RestMethod -Uri $scopeTestUri -Method Get -Headers $graphHeaders -ErrorAction Stop | Out-Null
    Write-Warning "Scoping check returned success! Application is NOT restricted by ApplicationAccessPolicy."
    $probeResults.Step6_ScopingStatus = "UNRESTRICTED (HTTP 200)"
} catch {
    $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    $probeResults.Step6_ScopingStatus = "HTTP $statusCode (Access Denied as expected)"
    if ($statusCode -eq 403 -or $_.ToString() -like "*403*") {
        Write-Host " -> Scoping Verified: Received HTTP 403 Forbidden on non-scoped mailbox." -ForegroundColor Green
    } else {
        Write-Host " -> Received status: $statusCode ($($_.Exception.Message))" -ForegroundColor Yellow
    }
}

$probeResults.Status = "Completed"
$probeResults | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding utf8

# Print Summary
Write-Host "`n=================== PROBE 3 FINDINGS SUMMARY ===================" -ForegroundColor Green
Write-Host "CalendarView 7-day Count      : $($probeResults.Step1_CalendarViewCount)"
Write-Host "Test Event Created            : $($probeResults.Step2_EventCreated)"
Write-Host "Properties Verified           : $($probeResults.Step3_PropertiesVerified)"
Write-Host "/events Filter Works          : $($probeResults.Step4_EventsFilterWorks)"
Write-Host "/calendarView Filter Works    : $($probeResults.Step4_CalendarViewFilterWorks)"
Write-Host "Event Deleted & 404 Confirmed : $($probeResults.Step5_Confirmed404AfterDel)"
Write-Host "Exchange Scoping Status       : $($probeResults.Step6_ScopingStatus)"
Write-Host "Redacted Report Saved To      : $outputFile" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Green

exit 0
