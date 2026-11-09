#Requires -Version 7.0
Set-StrictMode -Version Latest

$script:LogState = @{
    LogDirectory      = $null
    RunId             = "00000000-0000-0000-0000-000000000000"
    RetentionDays     = 90
    RegisteredSecrets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
}

function Initialize-SyncLog {
    <#
    .SYNOPSIS
        Initializes the daily rolling log directory, sets the active Run ID, and prunes expired logs.
    .DESCRIPTION
        Ensures the target log directory exists, stores module-scoped logging context, and removes
        any sync-YYYY-MM-DD.log files older than RetentionDays (default 90 days).
    .PARAMETER LogDirectory
        Directory path where daily log files are written.
    .PARAMETER RunId
        Unique identifier for the current execution run.
    .PARAMETER RetentionDays
        Number of days to retain daily log files. Defaults to 90.
    .PARAMETER ReferenceTimeUtc
        Optional UTC timestamp used for deterministic testing of log naming and retention pruning.
    .OUTPUTS
        System.String. Returns the full path to the active daily log file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RunId,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$RetentionDays = 90,

        [Parameter(Mandatory = $false)]
        [datetime]$ReferenceTimeUtc = [datetime]::UtcNow
    )

    if (-not (Test-Path -Path $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $resolvedDir = (Resolve-Path -Path $LogDirectory).Path
    $script:LogState.LogDirectory = $resolvedDir
    $script:LogState.RunId = $RunId
    $script:LogState.RetentionDays = $RetentionDays

    $cutoffUtc = $ReferenceTimeUtc.AddDays(-$RetentionDays).Date
    $existingLogs = Get-ChildItem -Path $resolvedDir -Filter "sync-*.log" -File -ErrorAction SilentlyContinue
    foreach ($file in $existingLogs) {
        if ($file.Name -match '^sync-(\d{4}-\d{2}-\d{2})\.log$') {
            $fileDate = [datetime]::MinValue
            $parsed = [datetime]::TryParseExact(
                $Matches[1],
                'yyyy-MM-dd',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$fileDate
            )
            if ($parsed -and $fileDate.ToUniversalTime().Date -lt $cutoffUtc) {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            }
        } elseif ($file.LastWriteTimeUtc.Date -lt $cutoffUtc) {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    $dateStamp = $ReferenceTimeUtc.ToUniversalTime().ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    return (Join-Path -Path $resolvedDir -ChildPath "sync-$dateStamp.log")
}

function Register-LogSecret {
    <#
    .SYNOPSIS
        Registers a sensitive string value for automatic redaction from all log messages.
    .DESCRIPTION
        Adds a non-empty secret string to the in-memory redaction list so that any accidental
        appearance of the secret in log messages is replaced with [REDACTED].
    .PARAMETER SecretValue
        The sensitive string to redact if encountered in log output.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SecretValue
    )

    if (-not [string]::IsNullOrWhiteSpace($SecretValue) -and $SecretValue.Length -ge 4) {
        [void]$script:LogState.RegisteredSecrets.Add($SecretValue)
    }
}

function Clear-LogSecret {
    <#
    .SYNOPSIS
        Clears all registered in-memory secret strings from the logger state.
    .DESCRIPTION
        Empties the module-scoped set of registered secret strings.
    #>
    [CmdletBinding()]
    param ()

    $script:LogState.RegisteredSecrets.Clear()
}

function Protect-LogMessage {
    <#
    .SYNOPSIS
        Redacts secrets, tokens, signatures, and registered sensitive values from a log message.
    .DESCRIPTION
        Scans the input string for query parameters (api_key, sig, shared_secret, client_assertion,
        access_token), Authorization Bearer tokens, JWT strings, and any registered literal secrets,
        replacing them with [REDACTED].
    .PARAMETER Message
        The raw log message string to sanitize.
    .OUTPUTS
        System.String. The redacted message safe for persistence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message
    )

    if ([string]::IsNullOrEmpty($Message)) {
        return $Message
    }

    $sanitized = $Message

    foreach ($secret in $script:LogState.RegisteredSecrets) {
        if (-not [string]::IsNullOrEmpty($secret) -and $sanitized.Contains($secret, [System.StringComparison]::OrdinalIgnoreCase)) {
            $escaped = [regex]::Escape($secret)
            $sanitized = [regex]::Replace($sanitized, $escaped, '[REDACTED]', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }

    # Redact query parameters: api_key, sig, shared_secret, client_assertion, access_token
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b(api_key|sig|shared_secret|sharedSecret|client_assertion|access_token)\s*([=:]\s*["'']?)([^"''&\s,}]+)',
        '$1$2[REDACTED]'
    )

    # Redact Bearer tokens
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)\b(Bearer)\s+[A-Za-z0-9\-\._~\+\/]+=*',
        '$1 [REDACTED]'
    )

    # Redact standalone JWT tokens (3 base64url segments starting with eyJ)
    $sanitized = [regex]::Replace(
        $sanitized,
        '\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        '[REDACTED_JWT]'
    )

    return $sanitized
}

function Write-SyncLog {
    <#
    .SYNOPSIS
        Writes a structured, UTC-timestamped, secret-redacted log entry to the daily log file.
    .DESCRIPTION
        Formats a single log line with ISO 8601 UTC timestamp, severity level, Run ID, and
        redacted message text, then appends it to logs/sync-YYYY-MM-DD.log.
    .PARAMETER Level
        Log severity level: INFO, WARN, ERROR, or DEBUG.
    .PARAMETER Message
        Log message text.
    .PARAMETER RunId
        Optional Run ID override. Defaults to the Run ID initialized in Initialize-SyncLog.
    .PARAMETER LogDirectory
        Optional LogDirectory override. Defaults to the directory initialized in Initialize-SyncLog.
    .PARAMETER TimestampUtc
        Optional UTC timestamp override for deterministic testing.
    .OUTPUTS
        System.String. Returns the formatted log line written to disk.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$RunId = $script:LogState.RunId,

        [Parameter(Mandatory = $false)]
        [string]$LogDirectory = $script:LogState.LogDirectory,

        [Parameter(Mandatory = $false)]
        [datetime]$TimestampUtc = [datetime]::UtcNow
    )

    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        throw "Logging has not been initialized. Call Initialize-SyncLog first or provide -LogDirectory."
    }

    if (-not (Test-Path -Path $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $utcNow = $TimestampUtc.ToUniversalTime()
    $isoTimestamp = $utcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $dateStamp = $utcNow.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $logFilePath = Join-Path -Path $LogDirectory -ChildPath "sync-$dateStamp.log"

    $safeMessage = Protect-LogMessage -Message $Message
    $logLine = "[$isoTimestamp] [$Level] [$RunId] $safeMessage"

    Add-Content -Path $logFilePath -Value $logLine -Encoding utf8
    return $logLine
}

function Format-SyncSummary {
    <#
    .SYNOPSIS
        Formats the end-of-run execution summary block matching ARCHITECTURE.md Section 15.
    .DESCRIPTION
        Produces the exact 19-line synchronization summary block required by ARCHITECTURE.md Section 15.
        Enforces the critical safety invariant that OutlookNativeModified must equal 0.
    .PARAMETER SummaryStats
        Hashtable containing run metrics (RunId, Timestamp, Mode, FacilityName, FacilityId,
        TargetMailbox, SourceRecordsRetrieved, Created, Updated, Recreated, Deleted, Unchanged,
        OutlookNativeInspected, OutlookNativeModified, ConflictsDetected, NotificationsDispatched,
        NotificationsSuppressed, Errors, CircuitBreaker, ExecutionResult).
    .OUTPUTS
        System.String. The formatted summary block.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SummaryStats
    )

    $outlookModified = if ($SummaryStats.ContainsKey('OutlookNativeModified')) { [int]$SummaryStats['OutlookNativeModified'] } else { 0 }
    if ($outlookModified -ne 0) {
        throw "CRITICAL SAFETY INVARIANT VIOLATION: Outlook-Native Modified count is $outlookModified (must be 0)."
    }

    $runId          = if ($SummaryStats.ContainsKey('RunId')) { [string]$SummaryStats['RunId'] } else { $script:LogState.RunId }
    $timestamp      = if ($SummaryStats.ContainsKey('Timestamp')) { [string]$SummaryStats['Timestamp'] } else { [datetime]::UtcNow.ToString('o') }
    $mode           = if ($SummaryStats.ContainsKey('Mode')) { [string]$SummaryStats['Mode'] } else { 'Production' }
    $facilityName   = if ($SummaryStats.ContainsKey('FacilityName')) { [string]$SummaryStats['FacilityName'] } else { 'Conference Room A' }
    $facilityId     = if ($SummaryStats.ContainsKey('FacilityId')) { [int]$SummaryStats['FacilityId'] } else { 100 }
    $targetMailbox  = if ($SummaryStats.ContainsKey('TargetMailbox')) { [string]$SummaryStats['TargetMailbox'] } else { 'roommailbox@example.com' }
    $sourceRecords  = if ($SummaryStats.ContainsKey('SourceRecordsRetrieved')) { [int]$SummaryStats['SourceRecordsRetrieved'] } else { 0 }
    $created        = if ($SummaryStats.ContainsKey('Created')) { [int]$SummaryStats['Created'] } else { 0 }
    $updated        = if ($SummaryStats.ContainsKey('Updated')) { [int]$SummaryStats['Updated'] } else { 0 }
    $recreated      = if ($SummaryStats.ContainsKey('Recreated')) { [int]$SummaryStats['Recreated'] } else { 0 }
    $deleted        = if ($SummaryStats.ContainsKey('Deleted')) { [int]$SummaryStats['Deleted'] } else { 0 }
    $unchanged      = if ($SummaryStats.ContainsKey('Unchanged')) { [int]$SummaryStats['Unchanged'] } else { 0 }
    $inspected      = if ($SummaryStats.ContainsKey('OutlookNativeInspected')) { [int]$SummaryStats['OutlookNativeInspected'] } else { 0 }
    $conflicts      = if ($SummaryStats.ContainsKey('ConflictsDetected')) { [int]$SummaryStats['ConflictsDetected'] } else { 0 }
    $notified       = if ($SummaryStats.ContainsKey('NotificationsDispatched')) { [int]$SummaryStats['NotificationsDispatched'] } else { 0 }
    $suppressed     = if ($SummaryStats.ContainsKey('NotificationsSuppressed')) { [int]$SummaryStats['NotificationsSuppressed'] } else { 0 }
    $errors         = if ($SummaryStats.ContainsKey('Errors')) { [int]$SummaryStats['Errors'] } else { 0 }
    $circuitBreaker = if ($SummaryStats.ContainsKey('CircuitBreaker')) { [string]$SummaryStats['CircuitBreaker'] } else { 'Armed / Normal' }
    $execResult     = if ($SummaryStats.ContainsKey('ExecutionResult')) { [string]$SummaryStats['ExecutionResult'] } else { 'SUCCESS (Exit Code 0)' }

    $lines = @(
        "======================= SYNCHRONIZATION SUMMARY ======================="
        "Run ID:                  $runId"
        "Timestamp:               $timestamp"
        "Mode:                    $mode"
        "ACTIVENet Facility:      $facilityName (ID: $facilityId)"
        "Target Mailbox:          $targetMailbox"
        "Source Records Retrieved: $sourceRecords"
        "Created:                 $created"
        "Updated:                 $updated"
        "Recreated:               $recreated"
        "Deleted:                 $deleted"
        "Unchanged:               $unchanged"
        "Outlook-Native Inspected: $inspected"
        "Outlook-Native Modified: 0  (CRITICAL INVARIANT)"
        "Conflicts Detected:      $conflicts"
        "Notifications Dispatched: $notified"
        "Notifications Suppressed: $suppressed"
        "Errors:                  $errors"
        "Circuit Breaker:         $circuitBreaker"
        "Execution Result:        $execResult"
        "======================================================================="
    )

    return ($lines -join [Environment]::NewLine)
}

function Write-SyncSummary {
    <#
    .SYNOPSIS
        Formats and writes the synchronization summary block to the active daily log file.
    .DESCRIPTION
        Calls Format-SyncSummary and appends the formatted block to the daily log file.
    .PARAMETER SummaryStats
        Hashtable of summary statistics matching ARCHITECTURE.md Section 15.
    .PARAMETER LogDirectory
        Optional LogDirectory override.
    .PARAMETER TimestampUtc
        Optional UTC timestamp override for deterministic log file selection.
    .OUTPUTS
        System.String. Returns the formatted summary block written to disk.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SummaryStats,

        [Parameter(Mandatory = $false)]
        [string]$LogDirectory = $script:LogState.LogDirectory,

        [Parameter(Mandatory = $false)]
        [datetime]$TimestampUtc = [datetime]::UtcNow
    )

    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        throw "Logging has not been initialized. Call Initialize-SyncLog first or provide -LogDirectory."
    }

    $summaryBlock = Format-SyncSummary -SummaryStats $SummaryStats
    $dateStamp = $TimestampUtc.ToUniversalTime().ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $logFilePath = Join-Path -Path $LogDirectory -ChildPath "sync-$dateStamp.log"

    Add-Content -Path $logFilePath -Value $summaryBlock -Encoding utf8
    return $summaryBlock
}

Export-ModuleMember -Function @(
    'Initialize-SyncLog',
    'Register-LogSecret',
    'Clear-LogSecret',
    'Protect-LogMessage',
    'Write-SyncLog',
    'Format-SyncSummary',
    'Write-SyncSummary'
)
