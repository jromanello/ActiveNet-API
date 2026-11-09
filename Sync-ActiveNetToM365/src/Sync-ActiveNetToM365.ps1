#Requires -Version 7.0
<#
.SYNOPSIS
    End-to-end orchestrator for one-way occupancy synchronization from ACTIVENet to Microsoft 365.
.DESCRIPTION
    Executes the ACTIVENet to Microsoft 365 Room Mailbox reconciliation pipeline
    per ARCHITECTURE.md Sections 8, 13, 15, and 17:
    - Acquires an exclusive PID-backed file lock (state/sync.lock).
    - Loads and validates local JSON state (state/sync_state.json); aborts on corruption (Exit Code 30)
      or enters ReconstructOnly mode if missing (Hard Constraint 2).
    - Authenticates to ACTIVENet (DPAPI SecureString + SHA-256 dynamic signature) and Microsoft Graph
      (X.509 certificate JWT client assertion).
    - Queries ACTIVENet GetFacilitySchedules and Microsoft Graph calendarView across the target window
      (30 days in -DryRun mode per Section 17.1; futureDaysWindow in Production mode).
    - Evaluates the pure reconciliation diff, ownership safety invariants, half-open conflict detection,
      and destructive-operation circuit breaker gates.
    - Dispatches planned actions through Invoke-CalendarAction:
      * When -DryRun is active: logs [WOULD CREATE], [WOULD UPDATE], [WOULD RECREATE], [WOULD DELETE],
        and [WOULD NOTIFY] without making any Graph write calls or modifying sync_state.json.
      * When -DryRun is not active: executes verified Graph mutations and atomically persists sync_state.json.
    - Emits the Section 15 Synchronization Summary block and releases the process lock.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to ../config/config.json relative to this script.
.PARAMETER DryRun
    Enforces read-only simulation mode over a 30-day window with zero Graph mutations and zero state writes.
.PARAMETER DaysWindow
    Optional override for the number of future days to query. Defaults to 30 in DryRun mode or futureDaysWindow (365) in Production.
.PARAMETER ReferenceNow
    Optional reference local DateTime for window calculation (defaults to Get-Date).
.PARAMETER PassThru
    When specified, returns the structured execution result PSCustomObject instead of calling exit.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\config\config.json'),

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 1095)]
    [int]$DaysWindow = 0,

    [Parameter(Mandatory = $false)]
    [datetime]$ReferenceNow = (Get-Date),

    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    [Parameter(Mandatory = $false)]
    [string]$RoomMailbox,

    [Parameter(Mandatory = $false)]
    [string]$ActiveNetOrgId,

    [Parameter(Mandatory = $false)]
    [string]$ActiveNetCenterName,

    [Parameter(Mandatory = $false)]
    [int]$ActiveNetCenterId = 0,

    [Parameter(Mandatory = $false)]
    [string]$ActiveNetFacilityName,

    [Parameter(Mandatory = $false)]
    [int]$ActiveNetFacilityId = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulesDir = Join-Path -Path $PSScriptRoot -ChildPath 'modules'
Import-Module (Join-Path $modulesDir 'Logging.psm1') -Force
Import-Module (Join-Path $modulesDir 'Locking.psm1') -Force
Import-Module (Join-Path $modulesDir 'Security.psm1') -Force
Import-Module (Join-Path $modulesDir 'ActiveNetClient.psm1') -Force
Import-Module (Join-Path $modulesDir 'GraphClient.psm1') -Force
Import-Module (Join-Path $modulesDir 'EventModel.psm1') -Force
Import-Module (Join-Path $modulesDir 'ConflictDetector.psm1') -Force
Import-Module (Join-Path $modulesDir 'StateManager.psm1') -Force
Import-Module (Join-Path $modulesDir 'ReconciliationEngine.psm1') -Force

function Resolve-RepoRelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RawPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseDirectory
    )

    if ([System.IO.Path]::IsPathRooted($RawPath)) {
        return [System.IO.Path]::GetFullPath($RawPath)
    }

    if ($RawPath -match '^\.\.[/\\]') {
        $trimmed = $RawPath -replace '^\.\.[/\\]', ''
        $candidateWithoutUp = Join-Path -Path $BaseDirectory -ChildPath $trimmed
        if (Test-Path $candidateWithoutUp -or (Test-Path (Split-Path $candidateWithoutUp -Parent))) {
            return [System.IO.Path]::GetFullPath($candidateWithoutUp)
        }
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $BaseDirectory -ChildPath $RawPath))
}

function Get-NormalizedSyncConfig {
    <#
    .SYNOPSIS
        Loads and normalizes configuration from either the flat host config.json format or nested schema format,
        applying CLI parameter overrides where provided.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationFilePath,

        [Parameter(Mandatory = $true)]
        [string]$ScriptDirectory,

        [Parameter(Mandatory = $false)]
        [string]$RoomMailbox,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetOrgId,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetCenterName,

        [Parameter(Mandatory = $false)]
        [int]$ActiveNetCenterId = 0,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetFacilityName,

        [Parameter(Mandatory = $false)]
        [int]$ActiveNetFacilityId = 0
    )

    if (-not (Test-Path -LiteralPath $ConfigurationFilePath -PathType Leaf)) {
        throw "Configuration file not found at '$ConfigurationFilePath'."
    }

    $repoRoot = Split-Path -Path $ScriptDirectory -Parent
    $rawJson = Get-Content -LiteralPath $ConfigurationFilePath -Raw -Encoding utf8 -ErrorAction Stop
    $parsed = $rawJson | ConvertFrom-Json -Depth 10 -ErrorAction Stop

    $hasNested = ($null -ne $parsed.PSObject.Properties['activeNet'] -and $null -ne $parsed.PSObject.Properties['microsoft365'])

    if ($hasNested) {
        $tenantId       = [string]$parsed.microsoft365.tenantId
        $clientId       = [string]$parsed.microsoft365.clientId
        $certThumbprint = [string]$parsed.microsoft365.certificateThumbprint
        $mailbox        = [string]$parsed.microsoft365.roomMailbox
        $timeZone       = if ($null -ne $parsed.microsoft365.PSObject.Properties['timeZone'] -and -not [string]::IsNullOrWhiteSpace([string]$parsed.microsoft365.timeZone)) { [string]$parsed.microsoft365.timeZone } else { 'Central Standard Time' }

        $orgId          = [string]$parsed.activeNet.organizationId
        $baseUrl        = [string]$parsed.activeNet.apiHost
        $credPathRaw    = [string]$parsed.activeNet.credentialPath
        $centerName     = [string]$parsed.activeNet.targetCenterName
        $centerId       = if ($null -ne $parsed.activeNet.PSObject.Properties['targetCenterId'] -and $null -ne $parsed.activeNet.targetCenterId) { [int]$parsed.activeNet.targetCenterId } else { 10 }
        $facilityName   = [string]$parsed.activeNet.targetFacilityName
        $facilityId     = [int]$parsed.activeNet.targetFacilityId

        $statePathRaw   = if ($null -ne $parsed.PSObject.Properties['paths'] -and $null -ne $parsed.paths.PSObject.Properties['stateFilePath']) { [string]$parsed.paths.stateFilePath } else { 'state/sync_state.json' }
        $logDirRaw      = if ($null -ne $parsed.PSObject.Properties['paths'] -and $null -ne $parsed.paths.PSObject.Properties['logDirectory']) { [string]$parsed.paths.logDirectory } else { 'logs' }
        $lockPathRaw    = if ($null -ne $parsed.PSObject.Properties['paths'] -and $null -ne $parsed.paths.PSObject.Properties['lockFilePath']) { [string]$parsed.paths.lockFilePath } else { 'state/sync.lock' }

        $futureDays     = if ($null -ne $parsed.PSObject.Properties['operationalSettings'] -and $null -ne $parsed.operationalSettings.PSObject.Properties['futureDaysWindow']) { [int]$parsed.operationalSettings.futureDaysWindow } else { 365 }
        $dryRunDays     = if ($null -ne $parsed.PSObject.Properties['operationalSettings'] -and $null -ne $parsed.operationalSettings.PSObject.Properties['dryRunDaysWindow']) { [int]$parsed.operationalSettings.dryRunDaysWindow } else { 30 }
        $chunkDays      = if ($null -ne $parsed.PSObject.Properties['operationalSettings'] -and $null -ne $parsed.operationalSettings.PSObject.Properties['chunkDays']) { [int]$parsed.operationalSettings.chunkDays } else { 90 }
        $retentionDays  = if ($null -ne $parsed.PSObject.Properties['operationalSettings'] -and $null -ne $parsed.operationalSettings.PSObject.Properties['logRetentionDays']) { [int]$parsed.operationalSettings.logRetentionDays } else { 90 }
        $maxDropPct     = if ($null -ne $parsed.PSObject.Properties['operationalSettings'] -and $null -ne $parsed.operationalSettings.PSObject.Properties['circuitBreakerMaxDeletesPct']) { [int]$parsed.operationalSettings.circuitBreakerMaxDeletesPct } else { 99 }
    } else {
        $tenantId       = [string]$parsed.tenantId
        $clientId       = [string]$parsed.clientId
        $certThumbprint = [string]$parsed.certThumbprint
        $mailbox        = [string]$parsed.mailbox
        $timeZone       = if ($null -ne $parsed.PSObject.Properties['timeZone'] -and -not [string]::IsNullOrWhiteSpace([string]$parsed.timeZone)) { [string]$parsed.timeZone } else { 'Central Standard Time' }

        $orgId          = [string]$parsed.activeNetOrgId
        $baseUrl        = [string]$parsed.activeNetBaseUrl
        $credPathRaw    = [string]$parsed.activeNetCredPath
        $centerName     = if ($null -ne $parsed.PSObject.Properties['centerName']) { [string]$parsed.centerName } else { 'Community Center Complex' }
        $centerId       = if ($null -ne $parsed.PSObject.Properties['centerId'] -and $null -ne $parsed.centerId) { [int]$parsed.centerId } else { 10 }
        $facilityName   = if ($null -ne $parsed.PSObject.Properties['facilityName']) { [string]$parsed.facilityName } else { 'Conference Room A' }
        $facilityId     = if ($null -ne $parsed.PSObject.Properties['facilityId'] -and $null -ne $parsed.facilityId) { [int]$parsed.facilityId } else { 100 }

        $statePathRaw   = if ($null -ne $parsed.PSObject.Properties['stateFilePath'] -and -not [string]::IsNullOrWhiteSpace([string]$parsed.stateFilePath)) { [string]$parsed.stateFilePath } else { 'state/sync_state.json' }
        $logDirRaw      = if ($null -ne $parsed.PSObject.Properties['logDirectory'] -and -not [string]::IsNullOrWhiteSpace([string]$parsed.logDirectory)) { [string]$parsed.logDirectory } else { 'logs' }
        $lockPathRaw    = if ($null -ne $parsed.PSObject.Properties['lockFilePath'] -and -not [string]::IsNullOrWhiteSpace([string]$parsed.lockFilePath)) { [string]$parsed.lockFilePath } else { 'state/sync.lock' }

        $futureDays     = if ($null -ne $parsed.PSObject.Properties['futureDaysWindow'] -and $null -ne $parsed.futureDaysWindow) { [int]$parsed.futureDaysWindow } else { 365 }
        $dryRunDays     = if ($null -ne $parsed.PSObject.Properties['dryRunDaysWindow'] -and $null -ne $parsed.dryRunDaysWindow) { [int]$parsed.dryRunDaysWindow } else { 30 }
        $chunkDays      = if ($null -ne $parsed.PSObject.Properties['chunkDays'] -and $null -ne $parsed.chunkDays) { [int]$parsed.chunkDays } else { 90 }
        $retentionDays  = if ($null -ne $parsed.PSObject.Properties['logRetentionDays'] -and $null -ne $parsed.logRetentionDays) { [int]$parsed.logRetentionDays } else { 90 }
        $maxDropPct     = if ($null -ne $parsed.PSObject.Properties['circuitBreakerMaxDeletesPct'] -and $null -ne $parsed.circuitBreakerMaxDeletesPct) { [int]$parsed.circuitBreakerMaxDeletesPct } else { 99 }
    }

    # CLI parameter overrides take precedence over config file values
    if (-not [string]::IsNullOrWhiteSpace($RoomMailbox)) {
        $mailbox = $RoomMailbox
    }
    if (-not [string]::IsNullOrWhiteSpace($ActiveNetOrgId)) {
        $orgId = $ActiveNetOrgId
    }
    if (-not [string]::IsNullOrWhiteSpace($ActiveNetCenterName)) {
        $centerName = $ActiveNetCenterName
    }
    if ($ActiveNetCenterId -gt 0) {
        $centerId = $ActiveNetCenterId
    }
    if (-not [string]::IsNullOrWhiteSpace($ActiveNetFacilityName)) {
        $facilityName = $ActiveNetFacilityName
    }
    if ($ActiveNetFacilityId -gt 0) {
        $facilityId = $ActiveNetFacilityId
    }

    return [PSCustomObject]@{
        TenantId                    = $tenantId
        ClientId                    = $clientId
        CertThumbprint              = $certThumbprint
        Mailbox                     = $mailbox
        TimeZone                    = $timeZone
        ActiveNetOrgId              = $orgId
        ActiveNetBaseUrl            = $baseUrl
        ActiveNetCredPath           = Resolve-RepoRelativePath -RawPath $credPathRaw -BaseDirectory $repoRoot
        CenterName                  = $centerName
        CenterId                    = $centerId
        FacilityName                = $facilityName
        FacilityId                  = $facilityId
        StateFilePath               = Resolve-RepoRelativePath -RawPath $statePathRaw -BaseDirectory $repoRoot
        LogDirectory                = Resolve-RepoRelativePath -RawPath $logDirRaw -BaseDirectory $repoRoot
        LockFilePath                = Resolve-RepoRelativePath -RawPath $lockPathRaw -BaseDirectory $repoRoot
        StateSchemaPath             = Resolve-RepoRelativePath -RawPath 'state/state.schema.json' -BaseDirectory $repoRoot
        FutureDaysWindow            = $futureDays
        DryRunDaysWindow            = $dryRunDays
        ChunkDays                   = $chunkDays
        LogRetentionDays            = $retentionDays
        CircuitBreakerMaxDeletesPct = $maxDropPct
    }
}

function Invoke-ActiveNetToM365Sync {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory = $false)]
        [switch]$IsDryRun,

        [Parameter(Mandatory = $false)]
        [int]$OverrideDaysWindow = 0,

        [Parameter(Mandatory = $false)]
        [datetime]$CurrentLocalTime = (Get-Date),

        [Parameter(Mandatory = $false)]
        [string]$RoomMailbox,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetOrgId,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetCenterName,

        [Parameter(Mandatory = $false)]
        [int]$ActiveNetCenterId = 0,

        [Parameter(Mandatory = $false)]
        [string]$ActiveNetFacilityName,

        [Parameter(Mandatory = $false)]
        [int]$ActiveNetFacilityId = 0
    )

    $runId = [guid]::NewGuid().ToString()
    $modeLabel = if ($IsDryRun.IsPresent) { 'DryRun' } else { 'Production' }
    $cfg = Get-NormalizedSyncConfig `
        -ConfigurationFilePath $ConfigurationPath `
        -ScriptDirectory $PSScriptRoot `
        -RoomMailbox $RoomMailbox `
        -ActiveNetOrgId $ActiveNetOrgId `
        -ActiveNetCenterName $ActiveNetCenterName `
        -ActiveNetCenterId $ActiveNetCenterId `
        -ActiveNetFacilityName $ActiveNetFacilityName `
        -ActiveNetFacilityId $ActiveNetFacilityId

    $logFilePath = Initialize-SyncLog -LogDirectory $cfg.LogDirectory -RunId $runId -RetentionDays $cfg.LogRetentionDays
    [void](Write-SyncLog -Level 'INFO' -Message "Starting ACTIVENet -> M365 Calendar Sync (Mode: $modeLabel, Facility: '$($cfg.FacilityName)' ID=$($cfg.FacilityId), Mailbox: '$($cfg.Mailbox)').")

    $lockHandle = $null
    $errorCount = 0

    try {
        # Step 1: Acquire non-blocking exclusive process lock
        $lockHandle = Lock-SyncProcess -LockFilePath $cfg.LockFilePath
        if ($null -eq $lockHandle) {
            [void](Write-SyncLog -Level 'WARN' -Message "Concurrent execution detected: Lock file '$($cfg.LockFilePath)' is held by another active process. Exiting with code 2.")
            return [PSCustomObject]@{
                RunId        = $runId
                Mode         = $modeLabel
                ExitCode     = 2
                LogFilePath  = $logFilePath
                SummaryBlock = $null
                PlanItems    = @()
            }
        }

        if ($lockHandle.ReclaimedStaleLock) {
            [void](Write-SyncLog -Level 'WARN' -Message "Reclaimed stale lock file '$($cfg.LockFilePath)' from a terminated process.")
        }

        # Step 2: Load and validate local JSON state
        $syncState = $null
        try {
            $schemaToUse = if (Test-Path -LiteralPath $cfg.StateSchemaPath -PathType Leaf) { $cfg.StateSchemaPath } else { '' }
            $syncState = Get-SyncState `
                -StateFilePath $cfg.StateFilePath `
                -DefaultFacilityId $cfg.FacilityId `
                -DefaultFacilityName $cfg.FacilityName `
                -SchemaFilePath $schemaToUse
        } catch {
            $errorCount++
            [void](Write-SyncLog -Level 'ERROR' -Message "Fatal state error: $($_.Exception.Message)")
            $corruptSummary = Write-SyncSummary -SummaryStats @{
                RunId                   = $runId
                Timestamp               = (Format-CentralIsoTimestamp -LocalDateTime $CurrentLocalTime)
                Mode                    = $modeLabel
                FacilityName            = $cfg.FacilityName
                FacilityId              = $cfg.FacilityId
                TargetMailbox           = $cfg.Mailbox
                SourceRecordsRetrieved  = 0
                Created                 = 0
                Updated                 = 0
                Recreated               = 0
                Deleted                 = 0
                Unchanged               = 0
                OutlookNativeInspected  = 0
                OutlookNativeModified   = 0
                ConflictsDetected       = 0
                NotificationsDispatched = 0
                NotificationsSuppressed = 0
                Errors                  = $errorCount
                CircuitBreaker          = 'Tripped - Corrupt State File'
                ExecutionResult         = 'FAILED (Exit Code 30 - Corrupt State)'
            }
            return [PSCustomObject]@{
                RunId        = $runId
                Mode         = $modeLabel
                ExitCode     = 30
                LogFilePath  = $logFilePath
                SummaryBlock = $corruptSummary
                PlanItems    = @()
            }
        }

        if ($syncState.IsMissing) {
            [void](Write-SyncLog -Level 'WARN' -Message "Local state file '$($cfg.StateFilePath)' does not exist. Entering ReconstructOnly mode (deletions locked).")
        } else {
            [void](Write-SyncLog -Level 'INFO' -Message "Loaded state file '$($cfg.StateFilePath)' with $($syncState.Records.Count) tracked record(s).")
        }

        # Step 3: Load DPAPI credentials and authenticate to Microsoft Graph
        $anSecrets = Get-ActiveNetCredential -ClixmlPath $cfg.ActiveNetCredPath
        Register-LogSecret -SecretValue (ConvertFrom-SecureStringPlain -SecureValue $anSecrets.ApiKey)
        Register-LogSecret -SecretValue (ConvertFrom-SecureStringPlain -SecureValue $anSecrets.SharedSecret)

        $graphToken = $null
        try {
            $authCert = Get-EntraAuthCertificate -Thumbprint $cfg.CertThumbprint -AllowCurrentUserFallback
            $jwtAssertion = New-EntraClientAssertionJwt -TenantId $cfg.TenantId -ClientId $cfg.ClientId -Certificate $authCert
            Register-LogSecret -SecretValue $jwtAssertion
            $graphToken = Connect-GraphApplication -TenantId $cfg.TenantId -ClientId $cfg.ClientId -ClientAssertionJwt $jwtAssertion
        } catch {
            $errorCount++
            [void](Write-SyncLog -Level 'ERROR' -Message "Microsoft Graph authentication failed: $($_.Exception.Message)")
            $authFailSummary = Write-SyncSummary -SummaryStats @{
                RunId                   = $runId
                Timestamp               = (Format-CentralIsoTimestamp -LocalDateTime $CurrentLocalTime)
                Mode                    = $modeLabel
                FacilityName            = $cfg.FacilityName
                FacilityId              = $cfg.FacilityId
                TargetMailbox           = $cfg.Mailbox
                SourceRecordsRetrieved  = 0
                Created                 = 0
                Updated                 = 0
                Recreated               = 0
                Deleted                 = 0
                Unchanged               = 0
                OutlookNativeInspected  = 0
                OutlookNativeModified   = 0
                ConflictsDetected       = 0
                NotificationsDispatched = 0
                NotificationsSuppressed = 0
                Errors                  = $errorCount
                CircuitBreaker          = 'Tripped - Graph Auth Failure'
                ExecutionResult         = 'FAILED (Exit Code 20 - Graph Auth Failure)'
            }
            return [PSCustomObject]@{
                RunId        = $runId
                Mode         = $modeLabel
                ExitCode     = 20
                LogFilePath  = $logFilePath
                SummaryBlock = $authFailSummary
                PlanItems    = @()
            }
        }

        [void](Write-SyncLog -Level 'INFO' -Message 'Successfully acquired Microsoft Graph application token.')

        # Step 4: Determine query window (30 days for DryRun per Section 17.1; FutureDaysWindow for Production)
        $effectiveDays = if ($OverrideDaysWindow -gt 0) {
            $OverrideDaysWindow
        } elseif ($IsDryRun.IsPresent) {
            $cfg.DryRunDaysWindow
        } else {
            $cfg.FutureDaysWindow
        }

        # Advance start window by 5 minutes so yyyy-MM-dd HH:mm truncation is always strictly in the future for ACTIVENet GetFacilitySchedules
        $windowStart = $CurrentLocalTime.AddMinutes(5)
        $windowEnd   = $windowStart.AddDays($effectiveDays)
        [void](Write-SyncLog -Level 'INFO' -Message "Querying window: $($windowStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($windowEnd.ToString('yyyy-MM-dd HH:mm:ss')) ($effectiveDays days).")

        # Step 5: Retrieve ACTIVENet facility schedules
        $anScheduleResult = Get-ActiveNetFacilitySchedule `
            -BaseUrl $cfg.ActiveNetBaseUrl `
            -OrgId $cfg.ActiveNetOrgId `
            -FacilityId $cfg.FacilityId `
            -StartDate $windowStart `
            -EndDate $windowEnd `
            -SecretPackage $anSecrets `
            -ChunkDays $cfg.ChunkDays

        $integrity = $anScheduleResult.Integrity
        $hasAuthHttpFailure = (@($integrity.httpStatuses | Where-Object { $_ -in @(401, 403) }).Count -gt 0)
        $hasAuthCodeFailure = (@($integrity.codesSeen | Where-Object { $_ -in @('0005', '0013') }).Count -gt 0)

        if (($hasAuthHttpFailure -or $hasAuthCodeFailure) -and $integrity.pagesFetched -eq 0) {
            $errorCount++
            [void](Write-SyncLog -Level 'ERROR' -Message "ACTIVENet authentication/signature error: $($integrity.errorMessage)")
            $anAuthSummary = Write-SyncSummary -SummaryStats @{
                RunId                   = $runId
                Timestamp               = (Format-CentralIsoTimestamp -LocalDateTime $CurrentLocalTime)
                Mode                    = $modeLabel
                FacilityName            = $cfg.FacilityName
                FacilityId              = $cfg.FacilityId
                TargetMailbox           = $cfg.Mailbox
                SourceRecordsRetrieved  = 0
                Created                 = 0
                Updated                 = 0
                Recreated               = 0
                Deleted                 = 0
                Unchanged               = 0
                OutlookNativeInspected  = 0
                OutlookNativeModified   = 0
                ConflictsDetected       = 0
                NotificationsDispatched = 0
                NotificationsSuppressed = 0
                Errors                  = $errorCount
                CircuitBreaker          = 'Tripped - ACTIVENet Auth Failure'
                ExecutionResult         = 'FAILED (Exit Code 11 - ACTIVENet Auth Failure)'
            }
            return [PSCustomObject]@{
                RunId        = $runId
                Mode         = $modeLabel
                ExitCode     = 11
                LogFilePath  = $logFilePath
                SummaryBlock = $anAuthSummary
                PlanItems    = @()
            }
        }

        if ($integrity.pagesFetched -eq 0 -and -not $integrity.isComplete) {
            $errorCount++
            [void](Write-SyncLog -Level 'ERROR' -Message "ACTIVENet API offline or unreachable: $($integrity.errorMessage)")
            $anOfflineSummary = Write-SyncSummary -SummaryStats @{
                RunId                   = $runId
                Timestamp               = (Format-CentralIsoTimestamp -LocalDateTime $CurrentLocalTime)
                Mode                    = $modeLabel
                FacilityName            = $cfg.FacilityName
                FacilityId              = $cfg.FacilityId
                TargetMailbox           = $cfg.Mailbox
                SourceRecordsRetrieved  = 0
                Created                 = 0
                Updated                 = 0
                Recreated               = 0
                Deleted                 = 0
                Unchanged               = 0
                OutlookNativeInspected  = 0
                OutlookNativeModified   = 0
                ConflictsDetected       = 0
                NotificationsDispatched = 0
                NotificationsSuppressed = 0
                Errors                  = $errorCount
                CircuitBreaker          = 'Tripped - ACTIVENet Unreachable'
                ExecutionResult         = 'FAILED (Exit Code 10 - ACTIVENet Unreachable)'
            }
            return [PSCustomObject]@{
                RunId        = $runId
                Mode         = $modeLabel
                ExitCode     = 10
                LogFilePath  = $logFilePath
                SummaryBlock = $anOfflineSummary
                PlanItems    = @()
            }
        }

        [void](Write-SyncLog -Level 'INFO' -Message "Retrieved $(@($anScheduleResult.Records).Count) raw schedule record(s) from ACTIVENet (PagesFetched=$($integrity.pagesFetched)/$($integrity.pagesExpected), Complete=$($integrity.isComplete)).")

        # Step 5b: Resolve Activity Details (event_notes & supervisor) for unique activity_numbers
        $rawActivityNumbers = @(
            @($anScheduleResult.Records) |
                Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['activity_number'] -and -not [string]::IsNullOrWhiteSpace([string]$_.activity_number) } |
                ForEach-Object { ([string]$_.activity_number).Trim() } |
                Select-Object -Unique
        )

        $activityDetailMap = @{}
        if ($rawActivityNumbers.Count -gt 0) {
            [void](Write-SyncLog -Level 'INFO' -Message "Fetching activity detail notes for $($rawActivityNumbers.Count) unique activity number(s): $($rawActivityNumbers -join ', ').")
            $activityDetailMap = Get-ActiveNetActivityDetailMap `
                -BaseUrl $cfg.ActiveNetBaseUrl `
                -OrgId $cfg.ActiveNetOrgId `
                -ActivityNumbers $rawActivityNumbers `
                -SecretPackage $anSecrets `
                -TargetFacilityId $cfg.FacilityId
        }

        # Step 6: Normalize ACTIVENet schedule records (each raw record emits up to 3 segments: Setup, Reservation, Teardown)
        $centralTz = Get-CentralTimeZoneInfo
        $normalizedEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($rawRec in @($anScheduleResult.Records)) {
            if ($null -eq $rawRec) { continue }
            foreach ($normEv in @(ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawRec -TimeZone $centralTz -ActivityDetailMap $activityDetailMap)) {
                if ($null -ne $normEv) {
                    $normalizedEvents.Add($normEv)
                }
            }
        }

        # Step 7: Retrieve Microsoft Graph room calendar events across the same window
        $calendarEvents = @(Get-RoomCalendarView `
            -AccessToken $graphToken `
            -Mailbox $cfg.Mailbox `
            -StartDateTime $windowStart `
            -EndDateTime $windowEnd `
            -TimeZone $cfg.TimeZone)

        [void](Write-SyncLog -Level 'INFO' -Message "Retrieved $($calendarEvents.Count) calendar event(s) from Microsoft Graph mailbox '$($cfg.Mailbox)'.")

        # Step 8: Filter state records to the queried window so out-of-window future/past records are not falsely flagged as deleted
        $inWindowStateRecords = @{}
        $outOfWindowFutureStateRecords = @{}
        $windowStartDto = ConvertTo-CentralDateTimeOffset -LocalDateTime $windowStart -TimeZone $centralTz
        $windowEndDto   = ConvertTo-CentralDateTimeOffset -LocalDateTime $windowEnd -TimeZone $centralTz

        foreach ($stateKey in $syncState.Records.Keys) {
            $rec = $syncState.Records[$stateKey]
            $recStartStr = if ($rec -is [System.Collections.IDictionary]) { [string]$rec['effectiveStart'] } else { [string]$rec.effectiveStart }
            $parsedStartDto = [System.DateTimeOffset]::MinValue
            if ([System.DateTimeOffset]::TryParse($recStartStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedStartDto)) {
                if ($parsedStartDto -ge $windowStartDto -and $parsedStartDto -le $windowEndDto) {
                    $inWindowStateRecords[$stateKey] = $rec
                } elseif ($parsedStartDto -gt $windowEndDto) {
                    $outOfWindowFutureStateRecords[$stateKey] = $rec
                }
            } else {
                $inWindowStateRecords[$stateKey] = $rec
            }
        }

        $scopedStateObject = [PSCustomObject]@{
            IsMissing = [bool]$syncState.IsMissing
            Mode      = [string]$syncState.Mode
            Records   = $inWindowStateRecords
        }

        # Step 9: Execute pure reconciliation diff
        $diffResult = Invoke-ReconciliationDiff `
            -NormalizedSourceEvents ($normalizedEvents.ToArray()) `
            -CalendarEvents $calendarEvents `
            -StateObject $scopedStateObject `
            -SourceIntegrityRecord $integrity `
            -IsStateMissing ([bool]$syncState.IsMissing) `
            -MaxAllowedDropPct $cfg.CircuitBreakerMaxDeletesPct

        if (-not $diffResult.CircuitBreaker.CanDelete) {
            [void](Write-SyncLog -Level 'WARN' -Message "Circuit Breaker status: $($diffResult.CircuitBreaker.StatusText)")
        } else {
            [void](Write-SyncLog -Level 'INFO' -Message "Circuit Breaker status: $($diffResult.CircuitBreaker.StatusText)")
        }

        # Step 10: Dispatch actions through Invoke-CalendarAction (enforces DryRun structural write isolation)
        $nextRecords = $diffResult.NextStateRecords
        foreach ($planItem in @($diffResult.PlanItems)) {
            if ($null -eq $planItem) { continue }

            try {
                $dispatchOutcome = Invoke-CalendarAction `
                    -PlanItem $planItem `
                    -AccessToken $graphToken `
                    -Mailbox $cfg.Mailbox `
                    -StateRecords $inWindowStateRecords `
                    -DryRun:$IsDryRun.IsPresent `
                    -TimeZone $cfg.TimeZone

                if ($planItem.Action -ne 'UNCHANGED') {
                    [void](Write-SyncLog -Level $dispatchOutcome.LogLevel -Message $dispatchOutcome.LogMessage)
                }

                if (-not $IsDryRun.IsPresent -and
                    $dispatchOutcome.Executed -and
                    $planItem.Action -in @('CREATE', 'RECREATE') -and
                    -not [string]::IsNullOrWhiteSpace($dispatchOutcome.GraphEventId)) {
                    $nextRecords[[string]$planItem.SourceScheduleId]['graphEventId'] = [string]$dispatchOutcome.GraphEventId
                }
            } catch {
                $errorCount++
                [void](Write-SyncLog -Level 'ERROR' -Message "Failed executing action '$($planItem.Action)' for SourceScheduleId='$($planItem.SourceScheduleId)': $($_.Exception.Message)")
            }
        }

        # Merge surviving out-of-window future state records
        foreach ($futureKey in $outOfWindowFutureStateRecords.Keys) {
            if (-not $nextRecords.Contains($futureKey)) {
                $nextRecords[$futureKey] = $outOfWindowFutureStateRecords[$futureKey]
            }
        }

        # Step 11: Persist state ONLY in Production mode (Section 17.4: Zero state mutation in DryRun)
        if ($IsDryRun.IsPresent) {
            [void](Write-SyncLog -Level 'INFO' -Message "DryRun mode active: Skipping state file persistence. Zero modifications made to '$($cfg.StateFilePath)'.")
        } else {
            $stateToSave = [ordered]@{
                schemaVersion              = '1.0.0'
                lastRunId                  = $runId
                lastSuccessfulRunTimestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                facilityId                 = $cfg.FacilityId
                facilityName               = $cfg.FacilityName
                records                    = $nextRecords
            }
            $schemaToUse = if (Test-Path -LiteralPath $cfg.StateSchemaPath -PathType Leaf) { $cfg.StateSchemaPath } else { '' }
            Save-SyncStateAtomic -StateData $stateToSave -StateFilePath $cfg.StateFilePath -SchemaFilePath $schemaToUse
            [void](Write-SyncLog -Level 'INFO' -Message "Atomically persisted updated state ($($nextRecords.Count) record(s)) to '$($cfg.StateFilePath)'.")
        }

        # Step 12: Emit Synchronization Summary Block
        $exitCode = if ($errorCount -eq 0) { 0 } else { 1 }
        $execResultLabel = if ($exitCode -eq 0) { 'SUCCESS (Exit Code 0)' } else { "PARTIAL FAILURE (Exit Code $exitCode)" }

        $summaryBlock = Write-SyncSummary -SummaryStats @{
            RunId                   = $runId
            Timestamp               = (Format-CentralIsoTimestamp -LocalDateTime $CurrentLocalTime -TimeZone $centralTz)
            Mode                    = $modeLabel
            FacilityName            = $cfg.FacilityName
            FacilityId              = $cfg.FacilityId
            TargetMailbox           = $cfg.Mailbox
            SourceRecordsRetrieved  = $diffResult.Summary.SourceRecordsRetrieved
            Created                 = $diffResult.Summary.Created
            Updated                 = $diffResult.Summary.Updated
            Recreated               = $diffResult.Summary.Recreated
            Deleted                 = $diffResult.Summary.Deleted
            Unchanged               = $diffResult.Summary.Unchanged
            OutlookNativeInspected  = $diffResult.Summary.OutlookNativeInspected
            OutlookNativeModified   = $diffResult.Summary.OutlookNativeModified
            ConflictsDetected       = $diffResult.Summary.ConflictsDetected
            NotificationsDispatched = $diffResult.Summary.NotificationsDispatched
            NotificationsSuppressed = $diffResult.Summary.NotificationsSuppressed
            Errors                  = $errorCount
            CircuitBreaker          = $diffResult.Summary.CircuitBreakerStatus
            ExecutionResult         = $execResultLabel
        }

        return [PSCustomObject]@{
            RunId          = $runId
            Mode           = $modeLabel
            ExitCode       = $exitCode
            LogFilePath    = $logFilePath
            Summary        = $diffResult.Summary
            SummaryBlock   = $summaryBlock
            PlanItems      = $diffResult.PlanItems
            CircuitBreaker = $diffResult.CircuitBreaker
        }
    } finally {
        Clear-LogSecret
        if ($null -ne $lockHandle) {
            Unlock-SyncProcess -LockHandle $lockHandle
        }
    }
}

$executionOutcome = Invoke-ActiveNetToM365Sync `
    -ConfigurationPath $ConfigPath `
    -IsDryRun:$DryRun.IsPresent `
    -OverrideDaysWindow $DaysWindow `
    -CurrentLocalTime $ReferenceNow `
    -RoomMailbox $RoomMailbox `
    -ActiveNetOrgId $ActiveNetOrgId `
    -ActiveNetCenterName $ActiveNetCenterName `
    -ActiveNetCenterId $ActiveNetCenterId `
    -ActiveNetFacilityName $ActiveNetFacilityName `
    -ActiveNetFacilityId $ActiveNetFacilityId

if (-not [string]::IsNullOrWhiteSpace($executionOutcome.SummaryBlock)) {
    Write-Information -MessageData $executionOutcome.SummaryBlock -InformationAction Continue
}

if ($PassThru.IsPresent) {
    return $executionOutcome
}

exit $executionOutcome.ExitCode
