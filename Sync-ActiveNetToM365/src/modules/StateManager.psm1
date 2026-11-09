#Requires -Version 7.0
Set-StrictMode -Version Latest

function Test-SyncStateSchema {
    <#
    .SYNOPSIS
        Validates a parsed state object or JSON string against the ActiveNetSyncState 1.0.0 schema.
    .DESCRIPTION
        Enforces all structural and type constraints defined in state/state.schema.json and
        ARCHITECTURE.md Section 6. Throws a descriptive validation error if any required field
        is missing or invalid.
    .PARAMETER StateObject
        The parsed PSCustomObject or IDictionary representing the sync state.
    .PARAMETER RawJson
        Optional raw JSON string to validate against SchemaFilePath via Test-Json when provided.
    .PARAMETER SchemaFilePath
        Optional path to state.schema.json for supplementary JSON Schema validation.
    .OUTPUTS
        System.Boolean. Returns $true if valid; throws on schema violation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$StateObject,

        [Parameter(Mandatory = $false)]
        [string]$RawJson = '',

        [Parameter(Mandatory = $false)]
        [string]$SchemaFilePath = ''
    )

    if ($null -eq $StateObject) {
        throw "Corrupt state: State object is null."
    }

    if (-not [string]::IsNullOrWhiteSpace($RawJson) -and
        -not [string]::IsNullOrWhiteSpace($SchemaFilePath) -and
        (Test-Path -LiteralPath $SchemaFilePath -PathType Leaf)) {
        $isJsonValid = Test-Json -Json $RawJson -SchemaFile $SchemaFilePath -ErrorAction SilentlyContinue
        if (-not $isJsonValid) {
            throw "Corrupt state: State JSON failed validation against schema file '$SchemaFilePath'."
        }
    }

    # Normalize property lookup helper
    $getProp = {
        param([object]$Obj, [string]$Name)
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($Name)) {
                return @{ Exists = $true; Value = $Obj[$Name] }
            }
            return @{ Exists = $false; Value = $null }
        }
        $prop = $Obj.PSObject.Properties[$Name]
        if ($null -ne $prop) {
            return @{ Exists = $true; Value = $prop.Value }
        }
        return @{ Exists = $false; Value = $null }
    }

    $requiredTopKeys = @(
        'schemaVersion',
        'lastRunId',
        'lastSuccessfulRunTimestamp',
        'facilityId',
        'facilityName',
        'records'
    )

    foreach ($reqKey in $requiredTopKeys) {
        $lookup = & $getProp $StateObject $reqKey
        if (-not $lookup.Exists -or $null -eq $lookup.Value) {
            throw "Corrupt state: Missing or null required top-level property '$reqKey'."
        }
    }

    $schemaVer = [string](& $getProp $StateObject 'schemaVersion').Value
    if ($schemaVer -cne '1.0.0') {
        throw "Corrupt state: Unsupported schemaVersion '$schemaVer'. Expected '1.0.0'."
    }

    $lastRunId = (& $getProp $StateObject 'lastRunId').Value
    if ($lastRunId -isnot [string] -or [string]::IsNullOrWhiteSpace($lastRunId)) {
        throw "Corrupt state: 'lastRunId' must be a non-empty string."
    }

    $lastTs = (& $getProp $StateObject 'lastSuccessfulRunTimestamp').Value
    if ($lastTs -isnot [string] -and $lastTs -isnot [datetime] -and $lastTs -isnot [System.DateTimeOffset]) {
        throw "Corrupt state: 'lastSuccessfulRunTimestamp' must be an ISO 8601 timestamp string."
    }
    $parsedTs = [System.DateTimeOffset]::MinValue
    if (-not [System.DateTimeOffset]::TryParse([string]$lastTs, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedTs)) {
        throw "Corrupt state: 'lastSuccessfulRunTimestamp' ('$lastTs') is not a valid ISO 8601 date-time."
    }

    $facId = (& $getProp $StateObject 'facilityId').Value
    if ($facId -isnot [int] -and $facId -isnot [long]) {
        throw "Corrupt state: 'facilityId' must be an integer."
    }

    $facName = (& $getProp $StateObject 'facilityName').Value
    if ($facName -isnot [string] -or [string]::IsNullOrWhiteSpace($facName)) {
        throw "Corrupt state: 'facilityName' must be a non-empty string."
    }

    $recordsObj = (& $getProp $StateObject 'records').Value
    if ($recordsObj -isnot [System.Collections.IDictionary] -and $recordsObj -isnot [PSCustomObject]) {
        throw "Corrupt state: 'records' must be a JSON object/dictionary."
    }

    $requiredRecordKeys = @(
        'sourceScheduleId',
        'graphEventId',
        'syncFingerprint',
        'effectiveStart',
        'effectiveEnd',
        'sourceStatus',
        'lastSynchronizedUtc'
    )

    $recordEntries = @()
    if ($recordsObj -is [System.Collections.IDictionary]) {
        foreach ($key in $recordsObj.Keys) {
            $recordEntries += [PSCustomObject]@{ Key = [string]$key; Record = $recordsObj[$key] }
        }
    } else {
        foreach ($prop in $recordsObj.PSObject.Properties) {
            $recordEntries += [PSCustomObject]@{ Key = [string]$prop.Name; Record = $prop.Value }
        }
    }

    foreach ($entry in $recordEntries) {
        $rec = $entry.Record
        if ($null -eq $rec) {
            throw "Corrupt state: Record '$($entry.Key)' is null."
        }

        foreach ($rKey in $requiredRecordKeys) {
            $rLookup = & $getProp $rec $rKey
            if (-not $rLookup.Exists -or $null -eq $rLookup.Value -or [string]::IsNullOrWhiteSpace([string]$rLookup.Value)) {
                throw "Corrupt state: Record '$($entry.Key)' is missing required property '$rKey'."
            }
        }

        $conflictLookup = & $getProp $rec 'activeConflict'
        if ($conflictLookup.Exists -and $null -ne $conflictLookup.Value) {
            $ac = $conflictLookup.Value
            $acKey = & $getProp $ac 'conflictKey'
            $acEvId = & $getProp $ac 'outlookEventId'
            if (-not $acKey.Exists -or [string]::IsNullOrWhiteSpace([string]$acKey.Value) -or
                -not $acEvId.Exists -or [string]::IsNullOrWhiteSpace([string]$acEvId.Value)) {
                throw "Corrupt state: Record '$($entry.Key)' has malformed 'activeConflict' object."
            }
        }
    }

    return $true
}

function ConvertTo-StateRecordHashtable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$RecordObject
    )

    $getVal = {
        param([object]$Obj, [string]$Name)
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($Name)) { return $Obj[$Name] }
            return $null
        }
        $p = $Obj.PSObject.Properties[$Name]
        if ($null -ne $p) { return $p.Value }
        return $null
    }

    $activeConflictVal = & $getVal $RecordObject 'activeConflict'
    $normalizedConflict = $null
    if ($null -ne $activeConflictVal) {
        $lastNotifiedVal = & $getVal $activeConflictVal 'lastNotifiedUtc'
        $normalizedConflict = [ordered]@{
            conflictKey           = [string](& $getVal $activeConflictVal 'conflictKey')
            outlookEventId        = [string](& $getVal $activeConflictVal 'outlookEventId')
            outlookOrganizerEmail = [string](& $getVal $activeConflictVal 'outlookOrganizerEmail')
            firstDetectedUtc      = [string](& $getVal $activeConflictVal 'firstDetectedUtc')
            lastNotifiedUtc       = if ($null -ne $lastNotifiedVal -and -not [string]::IsNullOrWhiteSpace([string]$lastNotifiedVal)) { [string]$lastNotifiedVal } else { $null }
        }
    }

    return [ordered]@{
        sourceScheduleId    = [string](& $getVal $RecordObject 'sourceScheduleId')
        graphEventId        = [string](& $getVal $RecordObject 'graphEventId')
        syncFingerprint     = [string](& $getVal $RecordObject 'syncFingerprint')
        effectiveStart      = [string](& $getVal $RecordObject 'effectiveStart')
        effectiveEnd        = [string](& $getVal $RecordObject 'effectiveEnd')
        sourceStatus        = [string](& $getVal $RecordObject 'sourceStatus')
        lastSynchronizedUtc = [string](& $getVal $RecordObject 'lastSynchronizedUtc')
        activeConflict      = $normalizedConflict
    }
}

function Get-SyncState {
    <#
    .SYNOPSIS
        Loads and validates the local JSON state file, or enters ReconstructOnly mode if absent.
    .DESCRIPTION
        Enforces Hard Constraint 2 and ARCHITECTURE.md Section 9 Scenarios 5 & 6:
        - If StateFilePath does not exist: returns a baseline state object with IsMissing = $true
          and Mode = 'ReconstructOnly' (reconstruct-only mode; never produces DELETE actions).
        - If StateFilePath exists on disk but is empty, malformed JSON, or fails schema validation:
          throws a fatal exception (ExitCode = 30, IsCorruptState = $true) to abort before any writes.
    .PARAMETER StateFilePath
        Path to state/sync_state.json.
    .PARAMETER DefaultFacilityId
        Default facilityId when initializing a missing state structure. Defaults to 440.
    .PARAMETER DefaultFacilityName
        Default facilityName when initializing a missing state structure. Defaults to 'NCC - Conference Room'.
    .PARAMETER SchemaFilePath
        Optional path to state/state.schema.json.
    .OUTPUTS
        PSCustomObject with IsMissing, Mode, SchemaVersion, LastRunId, LastSuccessfulRunTimestamp,
        FacilityId, FacilityName, and Records (hashtable).
    #>
    [CmdletBinding()]
    [Alias('Read-SyncState')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StateFilePath,

        [Parameter(Mandatory = $false)]
        [int]$DefaultFacilityId = 440,

        [Parameter(Mandatory = $false)]
        [string]$DefaultFacilityName = 'NCC - Conference Room',

        [Parameter(Mandatory = $false)]
        [string]$SchemaFilePath = ''
    )

    if (-not (Test-Path -LiteralPath $StateFilePath -PathType Leaf)) {
        return [PSCustomObject]@{
            IsMissing                  = $true
            Mode                       = 'ReconstructOnly'
            SchemaVersion              = '1.0.0'
            LastRunId                  = [guid]::Empty.ToString()
            LastSuccessfulRunTimestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            FacilityId                 = $DefaultFacilityId
            FacilityName               = $DefaultFacilityName
            Records                    = @{}
        }
    }

    try {
        $rawJson = Get-Content -LiteralPath $StateFilePath -Raw -Encoding utf8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($rawJson)) {
            throw "State file '$StateFilePath' is empty."
        }

        $parsed = $rawJson | ConvertFrom-Json -Depth 15 -ErrorAction Stop
        [void](Test-SyncStateSchema -StateObject $parsed -RawJson $rawJson -SchemaFilePath $SchemaFilePath)
    } catch {
        $errMsg = "FATAL STATE CORRUPTION: Failed to load or validate state file '$StateFilePath'. Execution aborted immediately. Details: $($_.Exception.Message)"
        $ex = [System.InvalidOperationException]::new($errMsg, $_.Exception)
        $ex.Data['ExitCode'] = 30
        $ex.Data['IsCorruptState'] = $true
        throw $ex
    }

    $recordsMap = @{}
    if ($null -ne $parsed.records) {
        foreach ($prop in $parsed.records.PSObject.Properties) {
            $recordsMap[[string]$prop.Name] = ConvertTo-StateRecordHashtable -RecordObject $prop.Value
        }
    }

    $lastTsStr = if ($parsed.lastSuccessfulRunTimestamp -is [datetime]) {
        $parsed.lastSuccessfulRunTimestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    } else {
        [string]$parsed.lastSuccessfulRunTimestamp
    }

    return [PSCustomObject]@{
        IsMissing                  = $false
        Mode                       = 'Normal'
        SchemaVersion              = [string]$parsed.schemaVersion
        LastRunId                  = [string]$parsed.lastRunId
        LastSuccessfulRunTimestamp = $lastTsStr
        FacilityId                 = [int]$parsed.facilityId
        FacilityName               = [string]$parsed.facilityName
        Records                    = $recordsMap
    }
}

function Save-SyncStateAtomic {
    <#
    .SYNOPSIS
        Atomically persists the synchronization state using a temporary file, schema validation, and backup.
    .DESCRIPTION
        Implements ARCHITECTURE.md Section 6 Atomic File Updates:
        1. Serializes StateData to $StateFilePath.tmp.
        2. Reads back and validates $StateFilePath.tmp against the state schema.
        3. Copies existing $StateFilePath to $StateFilePath.bak if present.
        4. Atomically replaces $StateFilePath with $StateFilePath.tmp.
    .PARAMETER StateData
        Hashtable or PSCustomObject containing the state to persist.
    .PARAMETER StateFilePath
        Target path for sync_state.json.
    .PARAMETER SchemaFilePath
        Optional path to state.schema.json for validation.
    #>
    [CmdletBinding()]
    [Alias('Write-SyncStateAtomic')]
    param (
        [Parameter(Mandatory = $true)]
        [object]$StateData,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StateFilePath,

        [Parameter(Mandatory = $false)]
        [string]$SchemaFilePath = ''
    )

    $parentDir = Split-Path -Path $StateFilePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir -PathType Container)) {
        [void](New-Item -Path $parentDir -ItemType Directory -Force)
    }

    $getField = {
        param([object]$Obj, [string]$PrimaryName, [string]$PascalName)
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($PrimaryName)) { return $Obj[$PrimaryName] }
            if ($Obj.Contains($PascalName)) { return $Obj[$PascalName] }
            return $null
        }
        if ($null -ne $Obj.PSObject.Properties[$PrimaryName]) { return $Obj.PSObject.Properties[$PrimaryName].Value }
        if ($null -ne $Obj.PSObject.Properties[$PascalName]) { return $Obj.PSObject.Properties[$PascalName].Value }
        return $null
    }

    $schemaVer = & $getField $StateData 'schemaVersion' 'SchemaVersion'
    if ([string]::IsNullOrWhiteSpace([string]$schemaVer)) { $schemaVer = '1.0.0' }

    $lastRunId = & $getField $StateData 'lastRunId' 'LastRunId'
    $lastTs    = & $getField $StateData 'lastSuccessfulRunTimestamp' 'LastSuccessfulRunTimestamp'
    $facId     = & $getField $StateData 'facilityId' 'FacilityId'
    $facName   = & $getField $StateData 'facilityName' 'FacilityName'
    $rawRecs   = & $getField $StateData 'records' 'Records'

    $orderedRecords = [ordered]@{}
    if ($null -ne $rawRecs) {
        if ($rawRecs -is [System.Collections.IDictionary]) {
            foreach ($k in ($rawRecs.Keys | Sort-Object)) {
                $orderedRecords[[string]$k] = ConvertTo-StateRecordHashtable -RecordObject $rawRecs[$k]
            }
        } else {
            foreach ($p in ($rawRecs.PSObject.Properties | Sort-Object -Property Name)) {
                $orderedRecords[[string]$p.Name] = ConvertTo-StateRecordHashtable -RecordObject $p.Value
            }
        }
    }

    $canonicalPayload = [ordered]@{
        schemaVersion              = [string]$schemaVer
        lastRunId                  = [string]$lastRunId
        lastSuccessfulRunTimestamp = [string]$lastTs
        facilityId                 = [int]$facId
        facilityName               = [string]$facName
        records                    = $orderedRecords
    }

    $tmpPath = "$StateFilePath.tmp"
    $bakPath = "$StateFilePath.bak"

    $jsonContent = $canonicalPayload | ConvertTo-Json -Depth 15
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($tmpPath, $jsonContent, $utf8NoBom)

    # Re-read and validate temporary file before touching existing state file
    try {
        $verifyRaw = Get-Content -LiteralPath $tmpPath -Raw -Encoding utf8 -ErrorAction Stop
        $verifyParsed = $verifyRaw | ConvertFrom-Json -Depth 15 -ErrorAction Stop
        [void](Test-SyncStateSchema -StateObject $verifyParsed -RawJson $verifyRaw -SchemaFilePath $SchemaFilePath)
    } catch {
        if (Test-Path -LiteralPath $tmpPath -PathType Leaf) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
        throw "Failed to validate temporary state file '$tmpPath' prior to atomic commit: $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $StateFilePath -PathType Leaf) {
        Copy-Item -LiteralPath $StateFilePath -Destination $bakPath -Force -ErrorAction Stop
    }

    Move-Item -LiteralPath $tmpPath -Destination $StateFilePath -Force -ErrorAction Stop
}

function Repair-SyncStateFromCalendar {
    <#
    .SYNOPSIS
        Reconstructs baseline state records in memory from calendar events carrying MAPI ownership proof.
    .DESCRIPTION
        Scans calendar events for MAPI extended property ActiveNetSyncOwned == 'True' and non-empty
        ActiveNetSourceId. Never guesses ownership from subject prefixes or similarity, and ignores
        all Outlook-native events.
    .PARAMETER CalendarEvents
        Array of Microsoft Graph calendar event objects.
    .OUTPUTS
        System.Collections.Hashtable keyed by ActiveNetSourceId.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [PSCustomObject[]]$CalendarEvents = @()
    )

    $reconstructed = @{}
    if ($null -eq $CalendarEvents -or $CalendarEvents.Count -eq 0) {
        return $reconstructed
    }

    $propGuid = '66f538b8-3e5e-4054-97c7-08051213f019'
    $propSyncOwned = "String {$propGuid} Name ActiveNetSyncOwned"
    $propSourceId  = "String {$propGuid} Name ActiveNetSourceId"

    foreach ($ev in $CalendarEvents) {
        if ($null -eq $ev) { continue }

        $syncOwnedVal = $null
        $sourceIdVal  = $null

        if ($null -ne $ev.PSObject.Properties['singleValueExtendedProperties'] -and
            $null -ne $ev.singleValueExtendedProperties) {
            foreach ($p in @($ev.singleValueExtendedProperties)) {
                if ($null -ne $p -and $null -ne $p.PSObject.Properties['id']) {
                    $idStr = [string]$p.id
                    $valStr = if ($null -ne $p.PSObject.Properties['value']) { [string]$p.value } else { $null }
                    if ($idStr.Equals($propSyncOwned, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $syncOwnedVal = $valStr
                    } elseif ($idStr.Equals($propSourceId, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $sourceIdVal = $valStr
                    }
                }
            }
        }

        if ($syncOwnedVal -ceq 'True' -and -not [string]::IsNullOrWhiteSpace($sourceIdVal)) {
            $graphId = if ($null -ne $ev.PSObject.Properties['id']) { [string]$ev.id } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($graphId)) {
                $startStr = if ($null -ne $ev.PSObject.Properties['start'] -and $null -ne $ev.start -and $null -ne $ev.start.PSObject.Properties['dateTime']) {
                    [string]$ev.start.dateTime
                } else {
                    [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                $endStr = if ($null -ne $ev.PSObject.Properties['end'] -and $null -ne $ev.end -and $null -ne $ev.end.PSObject.Properties['dateTime']) {
                    [string]$ev.end.dateTime
                } else {
                    [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                }

                $reconstructed[$sourceIdVal] = [ordered]@{
                    sourceScheduleId    = $sourceIdVal
                    graphEventId        = $graphId
                    syncFingerprint     = 'RECONSTRUCTED_PENDING_SYNC'
                    effectiveStart      = $startStr
                    effectiveEnd        = $endStr
                    sourceStatus        = 'Reconstructed'
                    lastSynchronizedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                    activeConflict      = $null
                }
            }
        }
    }

    return $reconstructed
}

Export-ModuleMember -Function @(
    'Test-SyncStateSchema',
    'Get-SyncState',
    'Save-SyncStateAtomic',
    'Repair-SyncStateFromCalendar'
) -Alias @(
    'Read-SyncState',
    'Write-SyncStateAtomic'
)
