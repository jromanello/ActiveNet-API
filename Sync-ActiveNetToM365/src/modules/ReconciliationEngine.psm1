#Requires -Version 7.0
Set-StrictMode -Version Latest

$script:MapiPropertyGuid = '66f538b8-3e5e-4054-97c7-08051213f019'
$script:PropIdSyncOwned  = "String {$script:MapiPropertyGuid} Name ActiveNetSyncOwned"
$script:PropIdSourceId   = "String {$script:MapiPropertyGuid} Name ActiveNetSourceId"

function Test-GraphEventOwnershipInternal {
    <#
    .SYNOPSIS
        Internal positive MAPI + state ownership evaluator for reconciliation classification.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$CalendarEvent,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$StateRecords,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedSourceId = ''
    )

    if ($null -eq $CalendarEvent -or $null -eq $StateRecords) {
        return $false
    }

    $syncOwnedVal = $null
    $sourceIdVal  = $null

    if ($null -ne $CalendarEvent.PSObject.Properties['singleValueExtendedProperties'] -and
        $null -ne $CalendarEvent.singleValueExtendedProperties) {
        foreach ($prop in @($CalendarEvent.singleValueExtendedProperties)) {
            if ($null -ne $prop -and $null -ne $prop.PSObject.Properties['id']) {
                $propId = [string]$prop.id
                $propVal = if ($null -ne $prop.PSObject.Properties['value']) { [string]$prop.value } else { $null }
                if ($propId.Equals($script:PropIdSyncOwned, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $syncOwnedVal = $propVal
                } elseif ($propId.Equals($script:PropIdSourceId, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $sourceIdVal = $propVal
                }
            }
        }
    }

    if ($syncOwnedVal -cne 'True' -or [string]::IsNullOrWhiteSpace($sourceIdVal)) {
        return $false
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceId) -and
        -not $sourceIdVal.Equals($ExpectedSourceId, [System.StringComparison]::Ordinal)) {
        return $false
    }

    if (-not $StateRecords.ContainsKey($sourceIdVal)) {
        return $false
    }

    $stateRec = $StateRecords[$sourceIdVal]
    $stateGraphId = if ($stateRec -is [System.Collections.IDictionary] -and $stateRec.Contains('graphEventId')) {
        [string]$stateRec['graphEventId']
    } elseif ($null -ne $stateRec.PSObject.Properties['graphEventId']) {
        [string]$stateRec.graphEventId
    } else {
        ''
    }

    $eventId = if ($null -ne $CalendarEvent.PSObject.Properties['id']) { [string]$CalendarEvent.id } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($stateGraphId) -and
        -not $eventId.Equals($stateGraphId, [System.StringComparison]::Ordinal)) {
        return $false
    }

    return $true
}

function Test-CircuitBreakerGate {
    <#
    .SYNOPSIS
        Evaluates all destructive-operation circuit breaker gates defined in ARCHITECTURE.md Section 10.2.
    .DESCRIPTION
        Enforces Hard Constraints 2 and 3 and ARCHITECTURE.md Section 10.2 before any DELETE action is permitted:
        1. HTTP Success Gate: All HTTP statuses in SourceIntegrityRecord must equal 200.
        2. API Response Code Gate: All ACTIVENet header response_codes must be '0000' or '0001'.
        3. Pagination Integrity Gate: isComplete must be $true and pagesFetched == pagesExpected.
        4. Volume Anomaly Gate: If previous state had > VolumeAnomalyMinBaseline (default 10) records
           and current active source count drops to 0 (or exceeds MaxAllowedDropPct), lock deletions.
        5. State Presence Gate (Hard Constraint 2): If IsStateMissing is $true, lock deletions.
    .PARAMETER SourceIntegrityRecord
        The integrity record returned by Get-ActiveNetFacilitySchedules.
    .PARAMETER CurrentActiveSourceCount
        Number of active (non-cancelled) source events in the current run.
    .PARAMETER PreviousStateRecordCount
        Number of tracked records in the previous local state file.
    .PARAMETER IsStateMissing
        Boolean indicating whether the state file was missing (ReconstructOnly mode).
    .PARAMETER VolumeAnomalyMinBaseline
        Minimum previous record count before the volume anomaly gate activates. Defaults to 10.
    .PARAMETER MaxAllowedDropPct
        Maximum percentage drop allowed when previous record count exceeds VolumeAnomalyMinBaseline.
        Defaults to 99 (trips when 100% drop / 0 records returned, or lower if configured).
    .OUTPUTS
        PSCustomObject detailing individual gate pass/fail flags, CanDelete boolean, and reasons.
    #>
    [CmdletBinding()]
    [Alias('Assert-CircuitBreaker')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [PSCustomObject]$SourceIntegrityRecord,

        [Parameter(Mandatory = $true)]
        [int]$CurrentActiveSourceCount,

        [Parameter(Mandatory = $true)]
        [int]$PreviousStateRecordCount,

        [Parameter(Mandatory = $false)]
        [bool]$IsStateMissing = $false,

        [Parameter(Mandatory = $false)]
        [int]$VolumeAnomalyMinBaseline = 10,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$MaxAllowedDropPct = 99
    )

    $reasons = [System.Collections.Generic.List[string]]::new()

    # Gate 1: HTTP Success Gate
    $httpGatePassed = $false
    if ($null -ne $SourceIntegrityRecord -and
        $null -ne $SourceIntegrityRecord.PSObject.Properties['httpStatuses'] -and
        $null -ne $SourceIntegrityRecord.httpStatuses -and
        @($SourceIntegrityRecord.httpStatuses).Count -gt 0) {
        $non200 = @($SourceIntegrityRecord.httpStatuses | Where-Object { [int]$_ -ne 200 })
        if ($non200.Count -eq 0) {
            $httpGatePassed = $true
        } else {
            $reasons.Add("HTTP Success Gate failed: Non-200 status codes seen ($($non200 -join ', ')).")
        }
    } else {
        $reasons.Add('HTTP Success Gate failed: No HTTP status records present in SourceIntegrityRecord.')
    }

    # Gate 2: API Response Code Gate
    $codeGatePassed = $false
    if ($null -ne $SourceIntegrityRecord -and
        $null -ne $SourceIntegrityRecord.PSObject.Properties['codesSeen'] -and
        $null -ne $SourceIntegrityRecord.codesSeen -and
        @($SourceIntegrityRecord.codesSeen).Count -gt 0) {
        $badCodes = @($SourceIntegrityRecord.codesSeen | Where-Object { ([string]$_) -notin @('0000', '0001') })
        if ($badCodes.Count -eq 0) {
            $codeGatePassed = $true
        } else {
            $reasons.Add("API Response Code Gate failed: Invalid response_code values seen ($($badCodes -join ', ')).")
        }
    } else {
        $reasons.Add('API Response Code Gate failed: No response_code values present in SourceIntegrityRecord.')
    }

    # Gate 3: Pagination Integrity Gate
    $paginationGatePassed = $false
    if ($null -ne $SourceIntegrityRecord -and
        $null -ne $SourceIntegrityRecord.PSObject.Properties['isComplete'] -and
        [bool]$SourceIntegrityRecord.isComplete -and
        $null -ne $SourceIntegrityRecord.PSObject.Properties['pagesFetched'] -and
        $null -ne $SourceIntegrityRecord.PSObject.Properties['pagesExpected'] -and
        [int]$SourceIntegrityRecord.pagesFetched -ge 1 -and
        [int]$SourceIntegrityRecord.pagesFetched -eq [int]$SourceIntegrityRecord.pagesExpected) {
        $paginationGatePassed = $true
    } else {
        $fetched  = if ($null -ne $SourceIntegrityRecord -and $null -ne $SourceIntegrityRecord.PSObject.Properties['pagesFetched']) { $SourceIntegrityRecord.pagesFetched } else { 0 }
        $expected = if ($null -ne $SourceIntegrityRecord -and $null -ne $SourceIntegrityRecord.PSObject.Properties['pagesExpected']) { $SourceIntegrityRecord.pagesExpected } else { -1 }
        $complete = if ($null -ne $SourceIntegrityRecord -and $null -ne $SourceIntegrityRecord.PSObject.Properties['isComplete']) { $SourceIntegrityRecord.isComplete } else { $false }
        $reasons.Add("Pagination Integrity Gate failed: isComplete=$complete, pagesFetched=$fetched, pagesExpected=$expected.")
    }

    # Gate 4: Volume Anomaly Gate (Sanity Threshold)
    $volumeGatePassed = $true
    if ($PreviousStateRecordCount -gt $VolumeAnomalyMinBaseline) {
        if ($CurrentActiveSourceCount -eq 0) {
            $volumeGatePassed = $false
            $reasons.Add("Volume Anomaly Gate failed: Previous state had $PreviousStateRecordCount active records, but current retrieval returned 0 active records.")
        } else {
            $dropPct = (($PreviousStateRecordCount - $CurrentActiveSourceCount) / [double]$PreviousStateRecordCount) * 100.0
            if ($dropPct -gt $MaxAllowedDropPct) {
                $volumeGatePassed = $false
                $reasons.Add("Volume Anomaly Gate failed: Source volume dropped by $([Math]::Round($dropPct, 1))% ($PreviousStateRecordCount -> $CurrentActiveSourceCount), exceeding threshold of $MaxAllowedDropPct%.")
            }
        }
    }

    # Gate 5: State Presence Gate (Hard Constraint 2)
    $statePresenceGatePassed = (-not $IsStateMissing)
    if ($IsStateMissing) {
        $reasons.Add('State Presence Gate failed: Local state file is missing (ReconstructOnly mode). Deletions are strictly prohibited.')
    }

    $canDelete = ($httpGatePassed -and $codeGatePassed -and $paginationGatePassed -and $volumeGatePassed -and $statePresenceGatePassed)
    $statusText = if ($canDelete) {
        'Armed / Normal'
    } else {
        "Tripped - Deletions Locked ($($reasons -join ' | '))"
    }

    return [PSCustomObject]@{
        CanDelete               = [bool]$canDelete
        HttpSuccessGatePassed   = [bool]$httpGatePassed
        ResponseCodeGatePassed  = [bool]$codeGatePassed
        PaginationGatePassed    = [bool]$paginationGatePassed
        VolumeAnomalyGatePassed = [bool]$volumeGatePassed
        StatePresenceGatePassed = [bool]$statePresenceGatePassed
        Reasons                 = $reasons.ToArray()
        StatusText              = $statusText
    }
}

function Invoke-ReconciliationDiff {
    <#
    .SYNOPSIS
        Pure reconciliation function that diffs normalized ACTIVENet events against Graph calendar events and local state.
    .DESCRIPTION
        Performs deterministic classification without making any network/API calls or disk mutations:
        - Enforces Hard Constraint 1: Partitioning of Sync-Owned vs Outlook-Native events requires both
          MAPI property ActiveNetSyncOwned == 'True' in {66f538b8-3e5e-4054-97c7-08051213f019} AND
          ActiveNetSourceId correlation. Never modifies or deletes Outlook-Native events.
        - Enforces Hard Constraints 2 & 3: Evaluates all Circuit Breaker gates and State Presence gate;
          suppresses all DELETE actions if any gate fails or if state is missing.
        - Evaluates half-open [Start, End) conflicts against Outlook-Native events, setting TargetShowAs = 'tentative'
          and emitting deduplicated NOTIFY decision objects.
        - Classifies actions into CREATE, UPDATE, RECREATE, DELETE, UNCHANGED, CONFLICT, and NOTIFY.
    .PARAMETER NormalizedSourceEvents
        Array of canonical NormalizedOccupancyEvent objects from EventModel.psm1.
    .PARAMETER CalendarEvents
        Array of Microsoft Graph calendar event objects from the target room mailbox.
    .PARAMETER StateObject
        State object returned by Get-SyncState (containing IsMissing, Mode, Records) or a hashtable of state records.
    .PARAMETER SourceIntegrityRecord
        Source integrity telemetry returned by Get-ActiveNetFacilitySchedules.
    .PARAMETER IsStateMissing
        Optional explicit override indicating state file is missing (ReconstructOnly mode).
    .PARAMETER VolumeAnomalyMinBaseline
        Minimum previous record count before the volume anomaly gate activates. Defaults to 10.
    .PARAMETER MaxAllowedDropPct
        Maximum percentage drop allowed before tripping the volume anomaly gate. Defaults to 99.
    .PARAMETER EvaluationTimestampUtc
        Optional UTC timestamp string used for projected state timestamps.
    .OUTPUTS
        PSCustomObject containing PlanItems, CircuitBreaker, NextStateRecords, SuppressedDeletes, and Summary.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [PSCustomObject[]]$NormalizedSourceEvents = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [PSCustomObject[]]$CalendarEvents = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$StateObject = $null,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [PSCustomObject]$SourceIntegrityRecord,

        [Parameter(Mandatory = $false)]
        [bool]$IsStateMissing = $false,

        [Parameter(Mandatory = $false)]
        [int]$VolumeAnomalyMinBaseline = 10,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$MaxAllowedDropPct = 99,

        [Parameter(Mandatory = $false)]
        [string]$EvaluationTimestampUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    )

    # Extract state records and missing-state flag
    $effectiveIsStateMissing = $IsStateMissing
    $inputStateRecords = @{}

    if ($null -eq $StateObject) {
        $effectiveIsStateMissing = $true
    } elseif ($StateObject -is [System.Collections.IDictionary]) {
        if ($StateObject.Contains('IsMissing') -and [bool]$StateObject['IsMissing']) {
            $effectiveIsStateMissing = $true
        }
        if ($StateObject.Contains('Mode') -and ([string]$StateObject['Mode']) -eq 'ReconstructOnly') {
            $effectiveIsStateMissing = $true
        }

        if ($StateObject.Contains('Records') -or $StateObject.Contains('records')) {
            $recsDict = if ($StateObject.Contains('Records')) { $StateObject['Records'] } else { $StateObject['records'] }
            if ($null -ne $recsDict) {
                if ($recsDict -is [System.Collections.IDictionary]) {
                    foreach ($k in $recsDict.Keys) {
                        $inputStateRecords[[string]$k] = $recsDict[$k]
                    }
                } else {
                    foreach ($p in $recsDict.PSObject.Properties) {
                        $inputStateRecords[[string]$p.Name] = $p.Value
                    }
                }
            }
        } else {
            foreach ($k in $StateObject.Keys) {
                $inputStateRecords[[string]$k] = $StateObject[$k]
            }
        }
    } else {
        if ($null -ne $StateObject.PSObject.Properties['IsMissing'] -and [bool]$StateObject.IsMissing) {
            $effectiveIsStateMissing = $true
        }
        if ($null -ne $StateObject.PSObject.Properties['Mode'] -and ([string]$StateObject.Mode) -eq 'ReconstructOnly') {
            $effectiveIsStateMissing = $true
        }
        $recsProp = if ($null -ne $StateObject.PSObject.Properties['Records']) {
            $StateObject.Records
        } elseif ($null -ne $StateObject.PSObject.Properties['records']) {
            $StateObject.records
        } else {
            $null
        }
        if ($null -ne $recsProp) {
            if ($recsProp -is [System.Collections.IDictionary]) {
                foreach ($k in $recsProp.Keys) {
                    $inputStateRecords[[string]$k] = $recsProp[$k]
                }
            } else {
                foreach ($p in $recsProp.PSObject.Properties) {
                    $inputStateRecords[[string]$p.Name] = $p.Value
                }
            }
        }
    }

    # If state is missing (ReconstructOnly mode), reconstruct in-memory correlation solely from MAPI extended properties
    $workingStateRecords = @{}
    if ($effectiveIsStateMissing) {
        foreach ($ev in @($CalendarEvents)) {
            if ($null -eq $ev) { continue }
            $syncOwnedVal = $null
            $sourceIdVal  = $null
            if ($null -ne $ev.PSObject.Properties['singleValueExtendedProperties'] -and $null -ne $ev.singleValueExtendedProperties) {
                foreach ($prop in @($ev.singleValueExtendedProperties)) {
                    if ($null -ne $prop -and $null -ne $prop.PSObject.Properties['id']) {
                        $propId = [string]$prop.id
                        $propVal = if ($null -ne $prop.PSObject.Properties['value']) { [string]$prop.value } else { $null }
                        if ($propId.Equals($script:PropIdSyncOwned, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $syncOwnedVal = $propVal
                        } elseif ($propId.Equals($script:PropIdSourceId, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $sourceIdVal = $propVal
                        }
                    }
                }
            }
            if ($syncOwnedVal -ceq 'True' -and -not [string]::IsNullOrWhiteSpace($sourceIdVal)) {
                $evId = if ($null -ne $ev.PSObject.Properties['id']) { [string]$ev.id } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($evId)) {
                    $workingStateRecords[$sourceIdVal] = [ordered]@{
                        sourceScheduleId    = $sourceIdVal
                        graphEventId        = $evId
                        syncFingerprint     = 'RECONSTRUCTED_FROM_MAPI'
                        effectiveStart      = ''
                        effectiveEnd        = ''
                        sourceStatus        = 'Reconstructed'
                        lastSynchronizedUtc = $EvaluationTimestampUtc
                        activeConflict      = $null
                    }
                }
            }
        }
    } else {
        foreach ($k in $inputStateRecords.Keys) {
            $workingStateRecords[$k] = $inputStateRecords[$k]
        }
    }

    # Filter active vs cancelled source events
    $activeSourceEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    $activeSourceMap = @{}
    foreach ($srcEv in @($NormalizedSourceEvents)) {
        if ($null -eq $srcEv) { continue }
        $isCancelled = ($null -ne $srcEv.PSObject.Properties['IsSourceCancelled'] -and [bool]$srcEv.IsSourceCancelled)
        if (-not $isCancelled) {
            $activeSourceEvents.Add($srcEv)
            $activeSourceMap[[string]$srcEv.SourceScheduleId] = $srcEv
        }
    }

    # Evaluate Destructive-Operation Circuit Breaker Gates
    $previousRecordCount = $inputStateRecords.Count
    $circuitBreaker = Test-CircuitBreakerGate `
        -SourceIntegrityRecord $SourceIntegrityRecord `
        -CurrentActiveSourceCount $activeSourceEvents.Count `
        -PreviousStateRecordCount $previousRecordCount `
        -IsStateMissing $effectiveIsStateMissing `
        -VolumeAnomalyMinBaseline $VolumeAnomalyMinBaseline `
        -MaxAllowedDropPct $MaxAllowedDropPct

    # Partition CalendarEvents into Sync-Owned (verified by MAPI + working state) and Outlook-Native
    $syncOwnedByGraphId = @{}
    $syncOwnedBySourceId = @{}
    $outlookNativeEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($calEv in @($CalendarEvents)) {
        if ($null -eq $calEv) { continue }
        $calId = if ($null -ne $calEv.PSObject.Properties['id']) { [string]$calEv.id } else { '' }

        $isOwned = Test-GraphEventOwnershipInternal -CalendarEvent $calEv -StateRecords $workingStateRecords
        if ($isOwned) {
            $sourceIdVal = ''
            foreach ($prop in @($calEv.singleValueExtendedProperties)) {
                if ($null -ne $prop -and ([string]$prop.id).Equals($script:PropIdSourceId, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $sourceIdVal = [string]$prop.value
                    break
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($calId)) {
                $syncOwnedByGraphId[$calId] = $calEv
            }
            if (-not [string]::IsNullOrWhiteSpace($sourceIdVal)) {
                $syncOwnedBySourceId[$sourceIdVal] = $calEv
            }
        } else {
            $outlookNativeEvents.Add($calEv)
        }
    }

    $planItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nextStateRecords = [ordered]@{}
    $suppressedDeletes = [System.Collections.Generic.List[string]]::new()

    $createdCount               = 0
    $updatedCount               = 0
    $recreatedCount             = 0
    $deletedCount               = 0
    $unchangedCount             = 0
    $conflictsDetectedCount     = 0
    $notificationsDispatched    = 0
    $notificationsSuppressed    = 0

    # Process each active source event
    foreach ($normEv in $activeSourceEvents) {
        $schedId = [string]$normEv.SourceScheduleId
        $existingStateRec = if ($workingStateRecords.ContainsKey($schedId)) { $workingStateRecords[$schedId] } else { $null }

        # Evaluate conflicts against Outlook-Native events using half-open [Start, End)
        $detectedConflicts = @(Find-CalendarConflict -NormalizedEvent $normEv -OutlookNativeEvents ($outlookNativeEvents.ToArray()))

        $nextActiveConflict = $null
        if ($detectedConflicts.Count -gt 0) {
            $normEv.HasConflict = $true
            $normEv.TargetShowAs = 'tentative'
            $primaryConflict = $detectedConflicts[0]
            $normEv.ConflictDetails = "Conflicting Outlook EventId=$($primaryConflict.OutlookEventId), Organizer=$($primaryConflict.OutlookOrganizerEmail)"

            foreach ($conf in $detectedConflicts) {
                $conflictsDetectedCount++
                $planItems.Add([PSCustomObject]@{
                    Action             = 'CONFLICT'
                    SourceScheduleId   = $schedId
                    NormalizedEvent    = $normEv
                    TargetGraphEventId = $conf.OutlookEventId
                    ConflictRecord     = $conf
                    Reason             = "Overlaps with Outlook-native meeting '$($conf.OutlookEventId)' [$($conf.OutlookStart.ToString('s')) - $($conf.OutlookEnd.ToString('s')))."
                })
            }

            # Notification deduplication check against previous state record's activeConflict
            $prevConflict = $null
            if ($null -ne $existingStateRec) {
                if ($existingStateRec -is [System.Collections.IDictionary] -and $existingStateRec.Contains('activeConflict')) {
                    $prevConflict = $existingStateRec['activeConflict']
                } elseif ($null -ne $existingStateRec.PSObject.Properties['activeConflict']) {
                    $prevConflict = $existingStateRec.activeConflict
                }
            }

            $prevConflictKey  = $null
            $prevLastNotified = $null
            $prevFirstDetect  = $null
            if ($null -ne $prevConflict) {
                if ($prevConflict -is [System.Collections.IDictionary]) {
                    $prevConflictKey  = [string]$prevConflict['conflictKey']
                    $prevLastNotified = $prevConflict['lastNotifiedUtc']
                    $prevFirstDetect  = $prevConflict['firstDetectedUtc']
                } else {
                    if ($null -ne $prevConflict.PSObject.Properties['conflictKey']) { $prevConflictKey = [string]$prevConflict.conflictKey }
                    if ($null -ne $prevConflict.PSObject.Properties['lastNotifiedUtc']) { $prevLastNotified = $prevConflict.lastNotifiedUtc }
                    if ($null -ne $prevConflict.PSObject.Properties['firstDetectedUtc']) { $prevFirstDetect = $prevConflict.firstDetectedUtc }
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($prevConflictKey) -and
                $prevConflictKey.Equals([string]$primaryConflict.ConflictKey, [System.StringComparison]::Ordinal) -and
                -not [string]::IsNullOrWhiteSpace([string]$prevLastNotified)) {
                # Duplicate conflict with unchanged ChangeKey -> suppress notification
                $notificationsSuppressed++
                $nextActiveConflict = [ordered]@{
                    conflictKey           = [string]$primaryConflict.ConflictKey
                    outlookEventId        = [string]$primaryConflict.OutlookEventId
                    outlookOrganizerEmail = [string]$primaryConflict.OutlookOrganizerEmail
                    firstDetectedUtc      = if (-not [string]::IsNullOrWhiteSpace([string]$prevFirstDetect)) { [string]$prevFirstDetect } else { $EvaluationTimestampUtc }
                    lastNotifiedUtc       = [string]$prevLastNotified
                }
            } else {
                # New or modified conflict -> emit NOTIFY decision item
                $notificationsDispatched++
                $planItems.Add([PSCustomObject]@{
                    Action             = 'NOTIFY'
                    SourceScheduleId   = $schedId
                    NormalizedEvent    = $normEv
                    TargetGraphEventId = [string]$primaryConflict.OutlookEventId
                    ConflictRecord     = $primaryConflict
                    Reason             = "New or updated conflict detected (ConflictKey=$($primaryConflict.ConflictKey)); notification decision queued for organizer '$($primaryConflict.OutlookOrganizerEmail)'."
                })
                $nextActiveConflict = [ordered]@{
                    conflictKey           = [string]$primaryConflict.ConflictKey
                    outlookEventId        = [string]$primaryConflict.OutlookEventId
                    outlookOrganizerEmail = [string]$primaryConflict.OutlookOrganizerEmail
                    firstDetectedUtc      = if (-not [string]::IsNullOrWhiteSpace([string]$prevFirstDetect)) { [string]$prevFirstDetect } else { $EvaluationTimestampUtc }
                    lastNotifiedUtc       = $EvaluationTimestampUtc
                }
            }
        } else {
            $normEv.HasConflict = $false
            $normEv.ConflictDetails = $null
            $normEv.TargetShowAs = if ($normEv.IsSourceTentative) { 'tentative' } else { 'busy' }
            $nextActiveConflict = $null
        }

        # Classify calendar action for this active source event
        if ($null -eq $existingStateRec) {
            $createdCount++
            $planItems.Add([PSCustomObject]@{
                Action             = 'CREATE'
                SourceScheduleId   = $schedId
                NormalizedEvent    = $normEv
                TargetGraphEventId = $null
                ConflictRecord     = $null
                Reason             = 'Active reservation has no existing correlation in state.'
            })

            $nextStateRecords[$schedId] = [ordered]@{
                sourceScheduleId    = $schedId
                graphEventId        = "PENDING_CREATE_$schedId"
                syncFingerprint     = [string]$normEv.SyncFingerprint
                effectiveStart      = [string]$normEv.EffectiveStartIso
                effectiveEnd        = [string]$normEv.EffectiveEndIso
                sourceStatus        = [string]$normEv.SourceStatus
                lastSynchronizedUtc = $EvaluationTimestampUtc
                activeConflict      = $nextActiveConflict
            }
        } else {
            $stateGraphId = if ($existingStateRec -is [System.Collections.IDictionary]) {
                [string]$existingStateRec['graphEventId']
            } else {
                [string]$existingStateRec.graphEventId
            }
            $stateFingerprint = if ($existingStateRec -is [System.Collections.IDictionary]) {
                [string]$existingStateRec['syncFingerprint']
            } else {
                [string]$existingStateRec.syncFingerprint
            }

            $verifiedGraphEvent = if ($syncOwnedBySourceId.ContainsKey($schedId)) {
                $syncOwnedBySourceId[$schedId]
            } else {
                $null
            }

            if ($null -eq $verifiedGraphEvent) {
                # Mapped Graph event is either missing from calendar (deleted in Outlook) or failed MAPI ownership verification (Scenario 7)
                $recreatedCount++
                $planItems.Add([PSCustomObject]@{
                    Action             = 'RECREATE'
                    SourceScheduleId   = $schedId
                    NormalizedEvent    = $normEv
                    TargetGraphEventId = $null
                    ConflictRecord     = $null
                    Reason             = "State record references Graph ID '$stateGraphId', which is missing from calendar or failed positive MAPI ownership verification."
                })

                $nextStateRecords[$schedId] = [ordered]@{
                    sourceScheduleId    = $schedId
                    graphEventId        = "PENDING_RECREATE_$schedId"
                    syncFingerprint     = [string]$normEv.SyncFingerprint
                    effectiveStart      = [string]$normEv.EffectiveStartIso
                    effectiveEnd        = [string]$normEv.EffectiveEndIso
                    sourceStatus        = [string]$normEv.SourceStatus
                    lastSynchronizedUtc = $EvaluationTimestampUtc
                    activeConflict      = $nextActiveConflict
                }
            } else {
                # Verified sync-owned event exists on calendar; check for fingerprint change or live calendar property drift
                $fingerprintChanged = (-not $stateFingerprint.Equals([string]$normEv.SyncFingerprint, [System.StringComparison]::Ordinal))

                $liveDriftReasons = [System.Collections.Generic.List[string]]::new()
                if ($null -ne $verifiedGraphEvent.PSObject.Properties['subject'] -and
                    -not ([string]$verifiedGraphEvent.subject).Equals([string]$normEv.OutlookSubject, [System.StringComparison]::Ordinal)) {
                    $liveDriftReasons.Add("subject drifted ('$($verifiedGraphEvent.subject)' != '$($normEv.OutlookSubject)')")
                }
                if ($null -ne $verifiedGraphEvent.PSObject.Properties['showAs'] -and
                    -not ([string]$verifiedGraphEvent.showAs).Equals([string]$normEv.TargetShowAs, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $liveDriftReasons.Add("showAs drifted ('$($verifiedGraphEvent.showAs)' != '$($normEv.TargetShowAs)')")
                }
                if ($null -ne $verifiedGraphEvent.PSObject.Properties['start'] -and
                    $null -ne $verifiedGraphEvent.start -and
                    $null -ne $verifiedGraphEvent.start.PSObject.Properties['dateTime']) {
                    $liveStart = [datetime]::Parse([string]$verifiedGraphEvent.start.dateTime, [System.Globalization.CultureInfo]::InvariantCulture)
                    if ($liveStart -ne [datetime]$normEv.EffectiveStart) {
                        $liveDriftReasons.Add("start time drifted ('$($liveStart.ToString('s'))' != '$($normEv.EffectiveStart.ToString('s'))')")
                    }
                }
                if ($null -ne $verifiedGraphEvent.PSObject.Properties['end'] -and
                    $null -ne $verifiedGraphEvent.end -and
                    $null -ne $verifiedGraphEvent.end.PSObject.Properties['dateTime']) {
                    $liveEnd = [datetime]::Parse([string]$verifiedGraphEvent.end.dateTime, [System.Globalization.CultureInfo]::InvariantCulture)
                    if ($liveEnd -ne [datetime]$normEv.EffectiveEnd) {
                        $liveDriftReasons.Add("end time drifted ('$($liveEnd.ToString('s'))' != '$($normEv.EffectiveEnd.ToString('s'))')")
                    }
                }

                if ($fingerprintChanged -or $liveDriftReasons.Count -gt 0) {
                    $updatedCount++
                    $reasonParts = [System.Collections.Generic.List[string]]::new()
                    if ($fingerprintChanged) {
                        $reasonParts.Add("SyncFingerprint changed ($stateFingerprint -> $($normEv.SyncFingerprint))")
                    }
                    if ($liveDriftReasons.Count -gt 0) {
                        $reasonParts.Add("Calendar drift detected: $($liveDriftReasons -join '; ')")
                    }

                    $planItems.Add([PSCustomObject]@{
                        Action             = 'UPDATE'
                        SourceScheduleId   = $schedId
                        NormalizedEvent    = $normEv
                        TargetGraphEventId = [string]$verifiedGraphEvent.id
                        ConflictRecord     = $null
                        Reason             = ($reasonParts -join ' | ')
                    })
                } else {
                    $unchangedCount++
                    $planItems.Add([PSCustomObject]@{
                        Action             = 'UNCHANGED'
                        SourceScheduleId   = $schedId
                        NormalizedEvent    = $normEv
                        TargetGraphEventId = [string]$verifiedGraphEvent.id
                        ConflictRecord     = $null
                        Reason             = 'SyncFingerprint and live calendar properties match authoritative source.'
                    })
                }

                $nextStateRecords[$schedId] = [ordered]@{
                    sourceScheduleId    = $schedId
                    graphEventId        = [string]$verifiedGraphEvent.id
                    syncFingerprint     = [string]$normEv.SyncFingerprint
                    effectiveStart      = [string]$normEv.EffectiveStartIso
                    effectiveEnd        = [string]$normEv.EffectiveEndIso
                    sourceStatus        = [string]$normEv.SourceStatus
                    lastSynchronizedUtc = $EvaluationTimestampUtc
                    activeConflict      = $nextActiveConflict
                }
            }
        }
    }

    # Evaluate records present in previous state that are absent from active source events (candidates for DELETE)
    if (-not $effectiveIsStateMissing) {
        foreach ($stateKey in $inputStateRecords.Keys) {
            if ($activeSourceMap.ContainsKey($stateKey)) {
                continue
            }

            $staleStateRec = $inputStateRecords[$stateKey]

            if (-not $circuitBreaker.CanDelete) {
                # Circuit breaker tripped -> suppress DELETE and retain record in state
                $suppressedDeletes.Add($stateKey)
                $nextStateRecords[$stateKey] = $staleStateRec
                continue
            }

            # Verify target event exists on calendar and passes positive MAPI ownership verification before planning DELETE
            if ($syncOwnedBySourceId.ContainsKey($stateKey)) {
                $verifiedToDelete = $syncOwnedBySourceId[$stateKey]
                $deletedCount++
                $planItems.Add([PSCustomObject]@{
                    Action             = 'DELETE'
                    SourceScheduleId   = $stateKey
                    NormalizedEvent    = $null
                    TargetGraphEventId = [string]$verifiedToDelete.id
                    ConflictRecord     = $null
                    Reason             = "Source schedule '$stateKey' is no longer active in ACTIVENet; circuit breaker gates passed and MAPI ownership verified."
                })
            } else {
                # Target Graph ID is either already gone from calendar or failed MAPI ownership check (Scenario 7) -> never issue DELETE against untagged/mismatched event
                $suppressedDeletes.Add($stateKey)
            }
        }
    }

    $summary = [PSCustomObject]@{
        SourceRecordsRetrieved  = @($NormalizedSourceEvents).Count
        ActiveSourceRecords     = $activeSourceEvents.Count
        Created                 = $createdCount
        Updated                 = $updatedCount
        Recreated               = $recreatedCount
        Deleted                 = $deletedCount
        Unchanged               = $unchangedCount
        OutlookNativeInspected  = $outlookNativeEvents.Count
        OutlookNativeModified   = 0
        ConflictsDetected       = $conflictsDetectedCount
        NotificationsDispatched = $notificationsDispatched
        NotificationsSuppressed = $notificationsSuppressed
        SuppressedDeletesCount  = $suppressedDeletes.Count
        CircuitBreakerStatus    = $circuitBreaker.StatusText
    }

    return [PSCustomObject]@{
        PlanItems         = $planItems.ToArray()
        CircuitBreaker    = $circuitBreaker
        NextStateRecords  = $nextStateRecords
        SuppressedDeletes = $suppressedDeletes.ToArray()
        Summary           = $summary
    }
}

function Invoke-CalendarAction {
    <#
    .SYNOPSIS
        Dispatches a single reconciliation plan item with structural Dry-Run write isolation.
    .DESCRIPTION
        Implements ARCHITECTURE.md Section 17.3 Structural Write Isolation:
        - When -DryRun is active, intercepts CREATE, UPDATE, RECREATE, DELETE, and NOTIFY items,
          constructs the corresponding [WOULD CREATE], [WOULD UPDATE], [WOULD RECREATE], [WOULD DELETE],
          or [WOULD NOTIFY] log message, and returns a simulated result without calling Microsoft Graph
          mutation functions or Invoke-RestMethod.
        - When -DryRun is false (Production), dispatches CREATE/RECREATE to New-RoomCalendarEvent,
          UPDATE to Set-RoomCalendarEvent (with mandatory MAPI re-verification), and DELETE to
          Remove-RoomCalendarEvent (with mandatory MAPI re-verification).
    .PARAMETER PlanItem
        A single plan item produced by Invoke-ReconciliationDiff.
    .PARAMETER AccessToken
        Microsoft Graph Bearer token (SecureString or string). Not required when -DryRun is active.
    .PARAMETER Mailbox
        Target room mailbox UPN/address (e.g., roommailbox@example.com).
    .PARAMETER StateRecords
        Local state records dictionary for pre-mutation ownership re-verification on UPDATE/DELETE.
    .PARAMETER DryRun
        When set, enforces read-only simulation with zero Graph write calls.
    .PARAMETER TimeZone
        Windows timezone identifier. Defaults to 'Central Standard Time'.
    .OUTPUTS
        PSCustomObject describing execution/simulation outcome, GraphEventId, LogLevel, and LogMessage.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Controlled dispatch wrapper with explicit -DryRun switch')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$PlanItem,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$AccessToken = $null,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$StateRecords = $null,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = 'Central Standard Time'
    )

    $action  = [string]$PlanItem.Action
    $schedId = [string]$PlanItem.SourceScheduleId
    $normEv  = $PlanItem.NormalizedEvent
    $targetId = if ($null -ne $PlanItem.PSObject.Properties['TargetGraphEventId'] -and $null -ne $PlanItem.TargetGraphEventId) {
        [string]$PlanItem.TargetGraphEventId
    } else {
        ''
    }

    if ($action -eq 'UNCHANGED') {
        return [PSCustomObject]@{
            Action           = 'UNCHANGED'
            SourceScheduleId = $schedId
            DryRun           = [bool]$DryRun.IsPresent
            Executed         = $false
            Simulated        = $false
            GraphEventId     = $targetId
            LogLevel         = 'DEBUG'
            LogMessage       = "[UNCHANGED] SourceId='$schedId' GraphId='$targetId' matches authoritative source."
        }
    }

    if ($action -eq 'CONFLICT') {
        $confRec = $PlanItem.ConflictRecord
        $orgEmail = if ($null -ne $confRec) { $confRec.OutlookOrganizerEmail } else { '' }
        return [PSCustomObject]@{
            Action           = 'CONFLICT'
            SourceScheduleId = $schedId
            DryRun           = [bool]$DryRun.IsPresent
            Executed         = $false
            Simulated        = [bool]$DryRun.IsPresent
            GraphEventId     = $targetId
            LogLevel         = 'WARN'
            LogMessage       = "[CONFLICT] SourceId='$schedId' overlaps with Outlook-native meeting '$targetId' (Organizer: '$orgEmail'). Reason: $($PlanItem.Reason)"
        }
    }

    # Structural Write Isolation Gate: DryRun intercepts before any Graph mutation call
    if ($DryRun.IsPresent) {
        switch ($action) {
            'CREATE' {
                $msg = "[WOULD CREATE] SourceId='$schedId' | Subject='$($normEv.OutlookSubject)' | Window='$($normEv.EffectiveStartIso) -> $($normEv.EffectiveEndIso)' | ShowAs='$($normEv.TargetShowAs)'"
                return [PSCustomObject]@{
                    Action           = 'CREATE'
                    SourceScheduleId = $schedId
                    DryRun           = $true
                    Executed         = $false
                    Simulated        = $true
                    GraphEventId     = "DRYRUN_CREATE_$schedId"
                    LogLevel         = 'INFO'
                    LogMessage       = $msg
                }
            }
            'RECREATE' {
                $msg = "[WOULD RECREATE] SourceId='$schedId' | Subject='$($normEv.OutlookSubject)' | Window='$($normEv.EffectiveStartIso) -> $($normEv.EffectiveEndIso)' | ShowAs='$($normEv.TargetShowAs)' | Reason: $($PlanItem.Reason)"
                return [PSCustomObject]@{
                    Action           = 'RECREATE'
                    SourceScheduleId = $schedId
                    DryRun           = $true
                    Executed         = $false
                    Simulated        = $true
                    GraphEventId     = "DRYRUN_RECREATE_$schedId"
                    LogLevel         = 'INFO'
                    LogMessage       = $msg
                }
            }
            'UPDATE' {
                $msg = "[WOULD UPDATE] SourceId='$schedId' | GraphId='$targetId' | Subject='$($normEv.OutlookSubject)' | Window='$($normEv.EffectiveStartIso) -> $($normEv.EffectiveEndIso)' | ShowAs='$($normEv.TargetShowAs)' | Reason: $($PlanItem.Reason)"
                return [PSCustomObject]@{
                    Action           = 'UPDATE'
                    SourceScheduleId = $schedId
                    DryRun           = $true
                    Executed         = $false
                    Simulated        = $true
                    GraphEventId     = $targetId
                    LogLevel         = 'INFO'
                    LogMessage       = $msg
                }
            }
            'DELETE' {
                $msg = "[WOULD DELETE] SourceId='$schedId' | GraphId='$targetId' | Reason: $($PlanItem.Reason)"
                return [PSCustomObject]@{
                    Action           = 'DELETE'
                    SourceScheduleId = $schedId
                    DryRun           = $true
                    Executed         = $false
                    Simulated        = $true
                    GraphEventId     = $targetId
                    LogLevel         = 'INFO'
                    LogMessage       = $msg
                }
            }
            'NOTIFY' {
                $confRec = $PlanItem.ConflictRecord
                $orgEmail = if ($null -ne $confRec) { $confRec.OutlookOrganizerEmail } else { '' }
                $confKey  = if ($null -ne $confRec) { $confRec.ConflictKey } else { '' }
                $msg = "[WOULD NOTIFY] SourceId='$schedId' | ConflictingOutlookId='$targetId' | Organizer='$orgEmail' | ConflictKey='$confKey'"
                return [PSCustomObject]@{
                    Action           = 'NOTIFY'
                    SourceScheduleId = $schedId
                    DryRun           = $true
                    Executed         = $false
                    Simulated        = $true
                    GraphEventId     = $targetId
                    LogLevel         = 'INFO'
                    LogMessage       = $msg
                }
            }
            default {
                throw "Unsupported reconciliation action type in DryRun: '$action'."
            }
        }
    }

    # Production Mutation Path (DryRun == $false)
    switch ($action) {
        'CREATE' {
            $bodyHtml = if ($null -ne $normEv.PSObject.Properties['BodyHtml']) { [string]$normEv.BodyHtml } else { '' }
            $created = New-RoomCalendarEvent `
                -AccessToken $AccessToken `
                -Mailbox $Mailbox `
                -Subject ([string]$normEv.OutlookSubject) `
                -StartDateTime ([datetime]$normEv.EffectiveStart) `
                -EndDateTime ([datetime]$normEv.EffectiveEnd) `
                -ShowAs ([string]$normEv.TargetShowAs) `
                -SourceScheduleId $schedId `
                -TimeZone $TimeZone `
                -BodyHtml $bodyHtml

            $newId = if ($null -ne $created -and $null -ne $created.PSObject.Properties['id']) { [string]$created.id } else { '' }
            return [PSCustomObject]@{
                Action           = 'CREATE'
                SourceScheduleId = $schedId
                DryRun           = $false
                Executed         = $true
                Simulated        = $false
                GraphEventId     = $newId
                LogLevel         = 'INFO'
                LogMessage       = "[CREATE] Created sync-owned event GraphId='$newId' for SourceId='$schedId' ('$($normEv.OutlookSubject)')."
            }
        }
        'RECREATE' {
            $bodyHtml = if ($null -ne $normEv.PSObject.Properties['BodyHtml']) { [string]$normEv.BodyHtml } else { '' }
            $recreated = New-RoomCalendarEvent `
                -AccessToken $AccessToken `
                -Mailbox $Mailbox `
                -Subject ([string]$normEv.OutlookSubject) `
                -StartDateTime ([datetime]$normEv.EffectiveStart) `
                -EndDateTime ([datetime]$normEv.EffectiveEnd) `
                -ShowAs ([string]$normEv.TargetShowAs) `
                -SourceScheduleId $schedId `
                -TimeZone $TimeZone `
                -BodyHtml $bodyHtml

            $newId = if ($null -ne $recreated -and $null -ne $recreated.PSObject.Properties['id']) { [string]$recreated.id } else { '' }
            return [PSCustomObject]@{
                Action           = 'RECREATE'
                SourceScheduleId = $schedId
                DryRun           = $false
                Executed         = $true
                Simulated        = $false
                GraphEventId     = $newId
                LogLevel         = 'INFO'
                LogMessage       = "[RECREATE] Recreated sync-owned event GraphId='$newId' for SourceId='$schedId' ('$($normEv.OutlookSubject)')."
            }
        }
        'UPDATE' {
            $bodyHtml = if ($null -ne $normEv.PSObject.Properties['BodyHtml']) { [string]$normEv.BodyHtml } else { '' }
            $updated = Set-RoomCalendarEvent `
                -AccessToken $AccessToken `
                -Mailbox $Mailbox `
                -EventId $targetId `
                -StateRecords $StateRecords `
                -ExpectedSourceId $schedId `
                -Subject ([string]$normEv.OutlookSubject) `
                -StartDateTime ([datetime]$normEv.EffectiveStart) `
                -EndDateTime ([datetime]$normEv.EffectiveEnd) `
                -ShowAs ([string]$normEv.TargetShowAs) `
                -TimeZone $TimeZone `
                -BodyHtml $bodyHtml

            $updId = if ($null -ne $updated -and $null -ne $updated.PSObject.Properties['id']) { [string]$updated.id } else { $targetId }
            return [PSCustomObject]@{
                Action           = 'UPDATE'
                SourceScheduleId = $schedId
                DryRun           = $false
                Executed         = $true
                Simulated        = $false
                GraphEventId     = $updId
                LogLevel         = 'INFO'
                LogMessage       = "[UPDATE] Updated sync-owned event GraphId='$updId' for SourceId='$schedId'. Reason: $($PlanItem.Reason)"
            }
        }
        'DELETE' {
            Remove-RoomCalendarEvent `
                -AccessToken $AccessToken `
                -Mailbox $Mailbox `
                -EventId $targetId `
                -StateRecords $StateRecords `
                -ExpectedSourceId $schedId

            return [PSCustomObject]@{
                Action           = 'DELETE'
                SourceScheduleId = $schedId
                DryRun           = $false
                Executed         = $true
                Simulated        = $false
                GraphEventId     = $targetId
                LogLevel         = 'INFO'
                LogMessage       = "[DELETE] Deleted sync-owned event GraphId='$targetId' for SourceId='$schedId'."
            }
        }
        'NOTIFY' {
            $confRec = $PlanItem.ConflictRecord
            $orgEmail = if ($null -ne $confRec) { $confRec.OutlookOrganizerEmail } else { '' }
            $confKey  = if ($null -ne $confRec) { $confRec.ConflictKey } else { '' }
            return [PSCustomObject]@{
                Action           = 'NOTIFY'
                SourceScheduleId = $schedId
                DryRun           = $false
                Executed         = $true
                Simulated        = $false
                GraphEventId     = $targetId
                LogLevel         = 'WARN'
                LogMessage       = "[NOTIFY] Conflict notification decision recorded for SourceId='$schedId' against OutlookId='$targetId' (Organizer='$orgEmail', ConflictKey='$confKey')."
            }
        }
        default {
            throw "Unsupported reconciliation action type: '$action'."
        }
    }
}

Export-ModuleMember -Function @(
    'Test-CircuitBreakerGate',
    'Invoke-ReconciliationDiff',
    'Invoke-CalendarAction'
) -Alias @(
    'Assert-CircuitBreaker'
)
