<#
.SYNOPSIS
    Validation Probe 2: ACTIVENet Facility Schedule Payload Analysis (Read-Only GET).
.DESCRIPTION
    Queries the ACTIVENet System API GetFacilitySchedules endpoint for the target facility
    over a 30-day future window to analyze raw response schema, field presence,
    timestamp timezone semantics, setup/teardown nullability, status representations,
    and composite key collision dynamics.
    Outputs redacted JSON to tools/probes/output/schedule-probe-<yyyyMMdd-HHmmss>.json.
    EXPLICITLY READ-ONLY: Never modifies source or destination data.
.PARAMETER ConfigPath
    Path to configuration JSON file. Defaults to config/config.json.
.PARAMETER FacilityId
    Optional facility ID override. If not specified, uses activeNet.facilityId from config.
.EXAMPLE
    pwsh -File ./tools/probes/Invoke-ActiveNetSchedulePayloadProbe.ps1 -ConfigPath "config/config.json"
.EXAMPLE
    pwsh -File ./tools/probes/Invoke-ActiveNetSchedulePayloadProbe.ps1 -FacilityId 2548
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator-facing probe requiring formatted console output')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot/../../config/config.json",

    [Parameter(Mandatory = $false)]
    [int]$FacilityId = 0
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
Write-Host " ACTIVENet Validation Probe 2: Schedule Payload Schema & Key Analysis " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Load Configuration
if (-not (Test-Path -Path $ConfigPath)) {
    Write-Error "Config file not found at: $ConfigPath"
    exit 1
}

$rawConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$orgId    = [string]$rawConfig.activeNetOrgId
$baseUrl  = [string]$rawConfig.activeNetBaseUrl
$credPath = [string]$rawConfig.activeNetCredPath

$targetFacilityId = if ($FacilityId -gt 0) {
    $FacilityId
} elseif ($null -ne $rawConfig.facilityId -and [int]$rawConfig.facilityId -gt 0) {
    [int]$rawConfig.facilityId
} else {
    Write-Error "No facilityId provided in config or parameter. Run Probe 1 first to identify target facility ID."
    exit 2
}

Write-Host "ActiveNet Org ID  : $orgId"
Write-Host "ActiveNet Host    : $baseUrl"
Write-Host "Target Facility ID: $targetFacilityId"

# 2. Load Credentials
if (-not (Test-Path -Path $credPath)) {
    Write-Error "Credential package not found at: $credPath. Run tools/Set-ActiveNetCredential.ps1 first."
    exit 3
}

try {
    $creds = Import-Clixml -Path $credPath
    $apiKey = ConvertFrom-SecureStringToPlain -SecureString $creds.ApiKey
    $sharedSecret = ConvertFrom-SecureStringToPlain -SecureString $creds.SharedSecret
} catch {
    Write-Error "Failed to decrypt ACTIVENet credentials via DPAPI. Ensure script is run as service account: $_"
    exit 4
}

$serviceName = "anet-systemapi-sec"
$probeTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "$PSScriptRoot/output"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$outputFile = Join-Path $outputDir "schedule-probe-$probeTimestamp.json"

# 3. Query Organization Timezone for comparison
Write-Host "`n[1/3] Retrieving organization timezone baseline..." -ForegroundColor Yellow
$orgTimeZone = "Unknown"
$orgBaseUri = "$baseUrl/$serviceName/$orgId/api/v1/organization?"
try {
    $orgResp = Invoke-ActiveNetGetWithRetry -BaseQueryUri $orgBaseUri -ApiKey $apiKey -SharedSecret $sharedSecret -Headers @{ "Accept" = "application/json" } -PacingDelayMs 1000
    if ($orgResp.body -and $orgResp.body.Count -gt 0) {
        $orgTimeZone = [string]$orgResp.body[0].time_zone
    }
} catch {
    Write-Warning "Could not query /organization for timezone verification: $_"
}
Write-Host " -> Configured ACTIVENet TimeZone: $orgTimeZone" -ForegroundColor Green

# 4. Query /facilityschedules for date range: (now + 5 mins) to (+30 days)
$dateFromDt = (Get-Date).AddMinutes(5)
$dateToDt = $dateFromDt.AddDays(30)
$dateFromStr = $dateFromDt.ToString("yyyy-MM-dd HH:mm")
$dateToStr   = $dateToDt.ToString("yyyy-MM-dd HH:mm")

Write-Host "`n[2/3] Querying /facilityschedules (DateFrom: $dateFromStr, DateTo: $dateToStr)..." -ForegroundColor Yellow

$allSchedules = [System.Collections.Generic.List[PSCustomObject]]::new()
$pageNumber = 1
$hasMorePages = $true

while ($hasMorePages) {
    $encodedDateFrom = [System.Uri]::EscapeDataString($dateFromStr)
    $encodedDateTo   = [System.Uri]::EscapeDataString($dateToStr)
    $schedBaseUri = "$baseUrl/$serviceName/$orgId/api/v1/facilityschedules?facility_ids=$targetFacilityId&date_from=$encodedDateFrom&date_to=$encodedDateTo"

    $pageInfoJson = @{
        page_number            = $pageNumber
        total_records_per_page = 500
    } | ConvertTo-Json -Compress

    $headers = @{
        "Accept"    = "application/json"
        "page_info" = $pageInfoJson
    }

    $schedResp = Invoke-ActiveNetGetWithRetry -BaseQueryUri $schedBaseUri -ApiKey $apiKey -SharedSecret $sharedSecret -Headers $headers -PacingDelayMs 2000

    if ($schedResp.headers.response_code -eq "0001") {
        Write-Host " -> Received 0001 (No results found in requested window)." -ForegroundColor Yellow
        break
    } elseif ($schedResp.headers.response_code -ne "0000") {
        throw "ActiveNet API error on /facilityschedules: Code $($schedResp.headers.response_code) - $($schedResp.headers.response_message)"
    }

    $records = $schedResp.body
    if ($null -eq $records -or $records.Count -eq 0) {
        $hasMorePages = $false
    } else {
        foreach ($r in $records) {
            $allSchedules.Add($r)
        }
        Write-Host " -> Page $($pageNumber): Fetched $($records.Count) schedule records (Total: $($allSchedules.Count))"
        if ($records.Count -lt 500) {
            $hasMorePages = $false
        } else {
            $pageNumber++
        }
    }
}

Write-Host "`n[3/3] Analyzing payload structure and key collision dynamics..." -ForegroundColor Yellow

# (a) Field names discovered
$allFieldNames = [System.Collections.Generic.HashSet[string]]::new()
foreach ($s in $allSchedules) {
    foreach ($prop in $s.PSObject.Properties) {
        $allFieldNames.Add($prop.Name) | Out-Null
    }
}
$hasNativeScheduleId = $allFieldNames.Contains("schedule_id")

# (b) Setup and Teardown null vs populated counts
$setupFromPopulated = 0
$setupFromNull = 0
$setupToPopulated = 0
$setupToNull = 0
$teardownFromPopulated = 0
$teardownFromNull = 0
$teardownToPopulated = 0
$teardownToNull = 0

# (c) Status values and cancellation detection
$permitStatusesSeen = [System.Collections.Generic.HashSet[string]]::new()
$activityStatusesSeen = [System.Collections.Generic.HashSet[string]]::new()
$scheduleTypesSeen = [System.Collections.Generic.HashSet[string]]::new()

# (d) Candidate composite keys for uniqueness evaluation
$candidateKeyA = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new()
$candidateKeyB = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new()
$candidateKeyC = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new()

# Timestamp sample
$timestampSamples = @()

foreach ($s in $allSchedules) {
    if ($s.setup_from_time) { $setupFromPopulated++ } else { $setupFromNull++ }
    if ($s.setup_to_time) { $setupToPopulated++ } else { $setupToNull++ }
    if ($s.tear_down_from_time) { $teardownFromPopulated++ } else { $teardownFromNull++ }
    if ($s.tear_down_to_time) { $teardownToPopulated++ } else { $teardownToNull++ }

    if ($s.permit_status) { $permitStatusesSeen.Add([string]$s.permit_status) | Out-Null }
    if ($s.activity_status) { $activityStatusesSeen.Add([string]$s.activity_status) | Out-Null }
    if ($s.schedule_type) { $scheduleTypesSeen.Add([string]$s.schedule_type) | Out-Null }

    # Composite Key Candidate A: {RefNum}_{start_date_time}
    $refNum = if ($s.permit_number) { "PERMIT_" + $s.permit_number } elseif ($s.activity_number) { "ACT_" + $s.activity_number } else { "SCHED_" + $s.schedule_type_id }
    $keyA = "$refNum`_$($s.start_date_time)"
    if (-not $candidateKeyA.ContainsKey($keyA)) { $candidateKeyA[$keyA] = [System.Collections.Generic.List[PSCustomObject]]::new() }
    $candidateKeyA[$keyA].Add($s)

    # Composite Key Candidate B: {RefNum}_{start_date_time}_{end_date_time}
    $keyB = "$refNum`_$($s.start_date_time)`_$($s.end_date_time)"
    if (-not $candidateKeyB.ContainsKey($keyB)) { $candidateKeyB[$keyB] = [System.Collections.Generic.List[PSCustomObject]]::new() }
    $candidateKeyB[$keyB].Add($s)

    # Composite Key Candidate C: Native schedule_id if present
    if ($hasNativeScheduleId -and $s.schedule_id) {
        $keyC = [string]$s.schedule_id
        if (-not $candidateKeyC.ContainsKey($keyC)) { $candidateKeyC[$keyC] = [System.Collections.Generic.List[PSCustomObject]]::new() }
        $candidateKeyC[$keyC].Add($s)
    }

    if ($timestampSamples.Count -lt 5) {
        $timestampSamples += [PSCustomObject]@{
            start_date_time     = $s.start_date_time
            end_date_time       = $s.end_date_time
            setup_from_time     = $s.setup_from_time
            tear_down_to_time   = $s.tear_down_to_time
        }
    }
}

# Determine collisions
$collisionsA = @($candidateKeyA.Keys | Where-Object { $candidateKeyA[$_].Count -gt 1 })
$collisionsB = @($candidateKeyB.Keys | Where-Object { $candidateKeyB[$_].Count -gt 1 })

# Redact schedules for JSON persistence
$redactedSchedules = @()
foreach ($s in $allSchedules) {
    $redactedSchedules += [PSCustomObject]@{
        facility_id         = $s.facility_id
        facility_name       = $s.facility_name
        start_date_time     = $s.start_date_time
        end_date_time       = $s.end_date_time
        setup_from_time     = $s.setup_from_time
        setup_to_time       = $s.setup_to_time
        tear_down_from_time = $s.tear_down_from_time
        tear_down_to_time   = $s.tear_down_to_time
        permit_number       = $s.permit_number
        permit_status       = $s.permit_status
        activity_number     = $s.activity_number
        activity_status     = $s.activity_status
        activity_name       = $s.activity_name
        event_type          = $s.event_type
        schedule_type       = $s.schedule_type
        schedule_type_id    = $s.schedule_type_id
        customer_first_hash = Get-RedactedHash -InputText $s.customer_first_name
        customer_last_hash  = Get-RedactedHash -InputText $s.customer_last_name
        company_name_hash   = Get-RedactedHash -InputText $s.company_name
    }
}

$probeReport = [ordered]@{
    ProbeName                  = "ActiveNetSchedulePayloadProbe"
    ExecutedUtc                = [DateTime]::UtcNow.ToString("o")
    TargetFacilityId           = $targetFacilityId
    DateRangeQuery             = "$dateFromStr to $dateToStr"
    TotalRecordsRetrieved      = $allSchedules.Count
    AllFieldNamesDiscovered    = @($allFieldNames | Sort-Object)
    HasNativeScheduleIdField   = $hasNativeScheduleId
    TimestampSamples           = $timestampSamples
    SetupTeardownStatistics    = [ordered]@{
        SetupFromTimePopulated   = $setupFromPopulated
        SetupFromTimeNull        = $setupFromNull
        SetupToTimePopulated     = $setupToPopulated
        SetupToTimeNull          = $setupToNull
        TeardownFromTimePopulated= $teardownFromPopulated
        TeardownFromTimeNull     = $teardownFromNull
        TeardownToTimePopulated  = $teardownToPopulated
        TeardownToTimeNull       = $teardownToNull
    }
    StatusValuesSeen           = [ordered]@{
        PermitStatuses   = @($permitStatusesSeen)
        ActivityStatuses = @($activityStatusesSeen)
        ScheduleTypes    = @($scheduleTypesSeen)
    }
    KeyUniquenessAnalysis      = [ordered]@{
        TotalRecords                = $allSchedules.Count
        CandidateKeyA_DistinctCount = $candidateKeyA.Keys.Count
        CandidateKeyA_Collisions    = $collisionsA.Count
        CandidateKeyB_DistinctCount = $candidateKeyB.Keys.Count
        CandidateKeyB_Collisions    = $collisionsB.Count
    }
    RecommendedKeyFormat       = if ($collisionsA.Count -eq 0 -and $allSchedules.Count -gt 0) {
        "Candidate A: {Ref}_{start_date_time}"
    } else {
        "Candidate B: {Ref}_{start_date_time}_{end_date_time}"
    }
    SampleRedactedRecords      = @($redactedSchedules | Select-Object -First 10)
}

$probeReport | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding utf8

# Print Summary Table
Write-Host "`n=================== PROBE 2 FINDINGS SUMMARY ===================" -ForegroundColor Green
Write-Host "Total Records Retrieved      : $($allSchedules.Count)"
Write-Host "Native 'schedule_id' Field   : $hasNativeScheduleId"
Write-Host "Setup Fields Populated       : $($setupFromPopulated)/$($allSchedules.Count)"
Write-Host "Teardown Fields Populated    : $($teardownToPopulated)/$($allSchedules.Count)"
Write-Host "Permit Statuses Discovered   : $(@($permitStatusesSeen) -join ', ')"
Write-Host "Activity Statuses Discovered : $(@($activityStatusesSeen) -join ', ')"
Write-Host "Schedule Types Discovered    : $(@($scheduleTypesSeen) -join ', ')"
Write-Host "Key Candidate A Collisions   : $($collisionsA.Count)"
Write-Host "Key Candidate B Collisions   : $($collisionsB.Count)"
Write-Host "Recommended Key Format       : $($probeReport.RecommendedKeyFormat)"
Write-Host "Redacted Report Saved To     : $outputFile" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Green

exit 0
