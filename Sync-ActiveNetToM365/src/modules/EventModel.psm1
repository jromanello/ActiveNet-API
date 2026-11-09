#Requires -Version 7.0
Set-StrictMode -Version Latest

function Get-CentralTimeZoneInfo {
    <#
    .SYNOPSIS
        Resolves the authoritative Central TimeZoneInfo object for America/Chicago.
    .DESCRIPTION
        Resolves 'Central Standard Time' (Windows) or 'America/Chicago' (IANA) to accurately
        compute UTC offsets across Daylight Saving Time transitions.
    .OUTPUTS
        System.TimeZoneInfo.
    #>
    [CmdletBinding()]
    [OutputType([System.TimeZoneInfo])]
    param ()

    try {
        return [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time')
    } catch {
        return [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago')
    }
}

function ConvertTo-CentralDateTimeOffset {
    <#
    .SYNOPSIS
        Converts a local Central time DateTime into a timezone-aware DateTimeOffset across DST boundaries.
    .DESCRIPTION
        Applies Central Standard Time / Central Daylight Time rules to an unspecified/local DateTime.
        If the local timestamp falls inside the spring-forward invalid hour gap, advances by 1 hour
        so GetUtcOffset does not fail. If ambiguous (fall-back hour), uses the standard time offset.
    .PARAMETER LocalDateTime
        The local wall-clock timestamp from ACTIVENet.
    .PARAMETER TimeZone
        Optional TimeZoneInfo override. Defaults to Central Time.
    .OUTPUTS
        System.DateTimeOffset.
    #>
    [CmdletBinding()]
    [OutputType([System.DateTimeOffset])]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$LocalDateTime,

        [Parameter(Mandatory = $false)]
        [System.TimeZoneInfo]$TimeZone = (Get-CentralTimeZoneInfo)
    )

    $unspecified = [datetime]::SpecifyKind($LocalDateTime, [System.DateTimeKind]::Unspecified)

    if ($TimeZone.IsInvalidTime($unspecified)) {
        $unspecified = $unspecified.AddHours(1)
    }

    $offset = $TimeZone.GetUtcOffset($unspecified)
    return [System.DateTimeOffset]::new($unspecified, $offset)
}

function Format-CentralIsoTimestamp {
    <#
    .SYNOPSIS
        Formats a local Central DateTime as an ISO 8601 string with explicit DST-aware UTC offset.
    .DESCRIPTION
        Converts the local DateTime using ConvertTo-CentralDateTimeOffset and formats as
        'yyyy-MM-ddTHH:mm:sszzz' (e.g., 2026-03-08T10:00:00-05:00 or 2026-11-01T10:00:00-06:00).
    .PARAMETER LocalDateTime
        The local wall-clock timestamp.
    .PARAMETER TimeZone
        Optional TimeZoneInfo override.
    .OUTPUTS
        System.String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$LocalDateTime,

        [Parameter(Mandatory = $false)]
        [System.TimeZoneInfo]$TimeZone = (Get-CentralTimeZoneInfo)
    )

    $dto = ConvertTo-CentralDateTimeOffset -LocalDateTime $LocalDateTime -TimeZone $TimeZone
    return $dto.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-EventSyncFingerprint {
    <#
    .SYNOPSIS
        Computes the deterministic SHA-256 SyncFingerprint for change detection.
    .DESCRIPTION
        Serializes CleanTitle|EffectiveStart(ISO)|EffectiveEnd(ISO)|IsSourceTentative (and optional NotesHash)
        using fixed UTF-8 formatting and returns the 64-character lowercase hex SHA-256 digest.
    .PARAMETER CleanTitle
        Sanitized event title (without [AN] or [Tentative] prefixes).
    .PARAMETER EffectiveStartIso
        Effective start timestamp in ISO 8601 format (yyyy-MM-ddTHH:mm:sszzz).
    .PARAMETER EffectiveEndIso
        Effective end timestamp in ISO 8601 format (yyyy-MM-ddTHH:mm:sszzz).
    .PARAMETER IsSourceTentative
        Boolean indicating whether ACTIVENet considers the reservation tentative.
    .PARAMETER NotesSummary
        Optional setup/context notes included in fingerprint calculation when non-empty.
    .OUTPUTS
        System.String. 64-character lowercase hexadecimal SHA-256 fingerprint.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CleanTitle,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EffectiveStartIso,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EffectiveEndIso,

        [Parameter(Mandatory = $true)]
        [bool]$IsSourceTentative,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$NotesSummary = ''
    )

    $tentativeToken = if ($IsSourceTentative) { 'true' } else { 'false' }
    $canonical = if ([string]::IsNullOrWhiteSpace($NotesSummary)) {
        "$CleanTitle|$EffectiveStartIso|$EffectiveEndIso|$tentativeToken"
    } else {
        "$CleanTitle|$EffectiveStartIso|$EffectiveEndIso|$tentativeToken|$($NotesSummary.Trim())"
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
}

function Get-ActiveNetCompositeKey {
    <#
    .SYNOPSIS
        Builds the deterministic Gate A Option A composite key ({Prefix}_{RefNum}_{start_date_time}).
    .DESCRIPTION
        Constructs the unique schedule identifier from the raw ACTIVENet schedule record:
        - Activities: ACT_{activity_number}_{start_date_time}
        - Permits / Internal Reservations: PERMIT_{permit_number}_{start_date_time}
        - Fallback: SCHED_{schedule_type_id}_{start_date_time}
    .PARAMETER RawScheduleRecord
        The raw schedule record object from GetFacilitySchedules.
    .OUTPUTS
        System.String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RawScheduleRecord
    )

    $startStr = if ($null -ne $RawScheduleRecord.PSObject.Properties['start_date_time'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.start_date_time)) {
        ([string]$RawScheduleRecord.start_date_time).Trim()
    } else {
        throw "RawScheduleRecord is missing mandatory 'start_date_time' field."
    }

    if ($null -ne $RawScheduleRecord.PSObject.Properties['activity_number'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.activity_number)) {
        $actNum = ([string]$RawScheduleRecord.activity_number).Trim()
        return "ACT_$actNum`_$startStr"
    }

    if ($null -ne $RawScheduleRecord.PSObject.Properties['permit_number'] -and
        $null -ne $RawScheduleRecord.permit_number -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.permit_number)) {
        $permNum = ([string]$RawScheduleRecord.permit_number).Trim()
        return "PERMIT_$permNum`_$startStr"
    }

    $schedTypeId = if ($null -ne $RawScheduleRecord.PSObject.Properties['schedule_type_id'] -and
        $null -ne $RawScheduleRecord.schedule_type_id) {
        ([string]$RawScheduleRecord.schedule_type_id).Trim()
    } else {
        '0'
    }

    return "SCHED_$schedTypeId`_$startStr"
}

function Format-EventBodyHtml {
    <#
    .SYNOPSIS
        Formats the HTML body for Setup, Reservation, and Teardown calendar events with operational context and setup notes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Setup', 'Reservation', 'Teardown')]
        [string]$SegmentType,

        [Parameter(Mandatory = $true)]
        [string]$CleanTitle,

        [Parameter(Mandatory = $true)]
        [string]$BookingType,

        [Parameter(Mandatory = $false)]
        [string]$SourceRef = '',

        [Parameter(Mandatory = $false)]
        [string]$EventType = '',

        [Parameter(Mandatory = $false)]
        [string]$Attendance = '',

        [Parameter(Mandatory = $false)]
        [string]$ContactOrSupervisor = '',

        [Parameter(Mandatory = $false)]
        [string]$EventNotes = ''
    )

    $enc = [System.Net.WebUtility]
    $lines = [System.Collections.Generic.List[string]]::new()

    if ($SegmentType -eq 'Setup') {
        $lines.Add("<p><strong>Setup for:</strong> $($enc::HtmlEncode($CleanTitle))</p>")
    } elseif ($SegmentType -eq 'Teardown') {
        $lines.Add("<p><strong>Tear Down for:</strong> $($enc::HtmlEncode($CleanTitle))</p>")
    } else {
        $lines.Add("<p><strong>Event:</strong> $($enc::HtmlEncode($CleanTitle))</p>")
    }

    if (-not [string]::IsNullOrWhiteSpace($EventNotes)) {
        $formattedNotes = $enc::HtmlEncode($EventNotes) -replace '\r?\n', '<br/>'
        $lines.Add("<p><strong>Setup / Event Notes:</strong><br/>$formattedNotes</p>")
    }

    $metaItems = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($BookingType)) {
        $refLabel = if (-not [string]::IsNullOrWhiteSpace($SourceRef)) {
            "$($enc::HtmlEncode($BookingType)) #$($enc::HtmlEncode($SourceRef))"
        } else {
            $enc::HtmlEncode($BookingType)
        }
        $metaItems.Add("<li><strong>Type / Reference:</strong> $refLabel</li>")
    }
    if (-not [string]::IsNullOrWhiteSpace($EventType)) {
        $metaItems.Add("<li><strong>Event Type:</strong> $($enc::HtmlEncode($EventType))</li>")
    }
    if (-not [string]::IsNullOrWhiteSpace($Attendance)) {
        $metaItems.Add("<li><strong>Attendance:</strong> $($enc::HtmlEncode($Attendance))</li>")
    }
    if (-not [string]::IsNullOrWhiteSpace($ContactOrSupervisor)) {
        $metaItems.Add("<li><strong>Contact / Supervisor:</strong> $($enc::HtmlEncode($ContactOrSupervisor))</li>")
    }

    if ($metaItems.Count -gt 0) {
        $lines.Add("<ul>$($metaItems -join '')</ul>")
    }

    $lines.Add('<hr/><p style="font-size:11px;color:#666666;">ACTIVENet Occupancy Projection. Managed automatically. Do not edit directly.</p>')
    return ($lines -join "`n")
}

function ConvertTo-NormalizedOccupancyEvent {
    <#
    .SYNOPSIS
        Transforms a raw ACTIVENet GetFacilitySchedules record into up to three canonical NormalizedOccupancyEvent objects (Setup, Reservation, Teardown).
    .DESCRIPTION
        Applies Gate A decisions and three-segment occupancy projection:
        1. Composite Key Option A: {Prefix}_{RefNum}_{start_date_time} for the main reservation, with _SETUP and _TEARDOWN suffixes for setup and tear down segments.
        2. Three-Event Split:
           - Setup Event: Emitted as a standalone event titled "Setup" from setup_from_time to setup_to_time (or start_date_time if setup_to_time is omitted) when setup_from_time is populated and SetupStart < SetupEnd.
           - Main Reservation Event: Emitted from start_date_time to end_date_time with subject "[AN] <CleanTitle>" or "[Tentative] [AN] <CleanTitle>".
           - Tear Down Event: Emitted as a standalone event titled "Tear Down" from tear_down_from_time (or end_date_time if tear_down_from_time is omitted) to tear_down_to_time when tear_down_to_time is populated and TeardownStart < TeardownEnd.
        3. Timezone: America/Chicago (US/Central) with DST-aware ISO 8601 serialization.
        4. Fingerprint: SHA-256 of CleanTitle|EffectiveStart(ISO)|EffectiveEnd(ISO)|IsSourceTentative (plus NotesSummary when present) for each segment.
    .PARAMETER RawScheduleRecord
        The raw schedule record returned by ACTIVENet GetFacilitySchedules.
    .PARAMETER TimeZone
        Optional TimeZoneInfo override. Defaults to Central Time.
    .PARAMETER ActivityDetailMap
        Optional hashtable keyed by activity_number containing EventNotes and Supervisor from Get-ActiveNetActivityDetailMap.
    .OUTPUTS
        PSCustomObject or PSCustomObject[] representing the canonical NormalizedOccupancyEvent segment(s).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RawScheduleRecord,

        [Parameter(Mandatory = $false)]
        [System.TimeZoneInfo]$TimeZone = (Get-CentralTimeZoneInfo),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$ActivityDetailMap = $null
    )

    $sourceScheduleId = Get-ActiveNetCompositeKey -RawScheduleRecord $RawScheduleRecord

    $bookingType = 'Other'
    $sourceRef = ''
    if ($null -ne $RawScheduleRecord.PSObject.Properties['activity_number'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.activity_number)) {
        $bookingType = 'Activity'
        $sourceRef = ([string]$RawScheduleRecord.activity_number).Trim()
    } elseif ($null -ne $RawScheduleRecord.PSObject.Properties['schedule_type'] -and
        ([string]$RawScheduleRecord.schedule_type) -match '(?i)Internal\s+Reservation') {
        $bookingType = 'InternalReservation'
        if ($null -ne $RawScheduleRecord.PSObject.Properties['permit_number'] -and $null -ne $RawScheduleRecord.permit_number) {
            $sourceRef = ([string]$RawScheduleRecord.permit_number).Trim()
        }
    } elseif ($null -ne $RawScheduleRecord.PSObject.Properties['permit_number'] -and
        $null -ne $RawScheduleRecord.permit_number -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.permit_number)) {
        $bookingType = 'Permit'
        $sourceRef = ([string]$RawScheduleRecord.permit_number).Trim()
    } elseif ($null -ne $RawScheduleRecord.PSObject.Properties['session_name'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.session_name)) {
        $bookingType = 'FlexReg'
        $sourceRef = ([string]$RawScheduleRecord.session_name).Trim()
    }

    $facilityId = if ($null -ne $RawScheduleRecord.PSObject.Properties['facility_id'] -and $null -ne $RawScheduleRecord.facility_id) {
        [int]$RawScheduleRecord.facility_id
    } else {
        0
    }

    $facilityName = if ($null -ne $RawScheduleRecord.PSObject.Properties['facility_name'] -and $null -ne $RawScheduleRecord.facility_name) {
        ([string]$RawScheduleRecord.facility_name).Trim()
    } else {
        ''
    }

    $resStart = [datetime]::Parse([string]$RawScheduleRecord.start_date_time, [System.Globalization.CultureInfo]::InvariantCulture)
    $resEnd   = [datetime]::Parse([string]$RawScheduleRecord.end_date_time, [System.Globalization.CultureInfo]::InvariantCulture)

    $setupStart = $null
    if ($null -ne $RawScheduleRecord.PSObject.Properties['setup_from_time'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.setup_from_time)) {
        $setupStart = [datetime]::Parse([string]$RawScheduleRecord.setup_from_time, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $setupEnd = $null
    if ($null -ne $RawScheduleRecord.PSObject.Properties['setup_to_time'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.setup_to_time)) {
        $setupEnd = [datetime]::Parse([string]$RawScheduleRecord.setup_to_time, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $teardownStart = $null
    if ($null -ne $RawScheduleRecord.PSObject.Properties['tear_down_from_time'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.tear_down_from_time)) {
        $teardownStart = [datetime]::Parse([string]$RawScheduleRecord.tear_down_from_time, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $teardownEnd = $null
    if ($null -ne $RawScheduleRecord.PSObject.Properties['tear_down_to_time'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.tear_down_to_time)) {
        $teardownEnd = [datetime]::Parse([string]$RawScheduleRecord.tear_down_to_time, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $rawTitleCandidates = @(
        if ($null -ne $RawScheduleRecord.PSObject.Properties['activity_name']) { [string]$RawScheduleRecord.activity_name } else { '' }
        if ($null -ne $RawScheduleRecord.PSObject.Properties['session_name']) { [string]$RawScheduleRecord.session_name } else { '' }
        if ($null -ne $RawScheduleRecord.PSObject.Properties['league_name']) { [string]$RawScheduleRecord.league_name } else { '' }
        if ($null -ne $RawScheduleRecord.PSObject.Properties['event_description']) { [string]$RawScheduleRecord.event_description } else { '' }
        if ($null -ne $RawScheduleRecord.PSObject.Properties['event_type']) { [string]$RawScheduleRecord.event_type } else { '' }
        if ($null -ne $RawScheduleRecord.PSObject.Properties['schedule_type']) { [string]$RawScheduleRecord.schedule_type } else { '' }
    )

    $rawEventName = 'Facility Reservation'
    foreach ($candidate in $rawTitleCandidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $rawEventName = $candidate
            break
        }
    }

    $cleanTitle = ([regex]::Replace($rawEventName, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($cleanTitle)) {
        $cleanTitle = 'Facility Reservation'
    }

    # Extract operational context for Maintenance (Attendance, EventType, Contact/Supervisor, and Activity EventNotes)
    $eventTypeStr = if ($null -ne $RawScheduleRecord.PSObject.Properties['event_type'] -and -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.event_type)) {
        ([string]$RawScheduleRecord.event_type).Trim()
    } else {
        ''
    }

    $attendanceStr = if ($null -ne $RawScheduleRecord.PSObject.Properties['attendance'] -and $null -ne $RawScheduleRecord.attendance -and -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.attendance)) {
        ([string]$RawScheduleRecord.attendance).Trim()
    } else {
        ''
    }

    $firstName = if ($null -ne $RawScheduleRecord.PSObject.Properties['customer_first_name'] -and -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.customer_first_name)) {
        ([string]$RawScheduleRecord.customer_first_name).Trim()
    } else {
        ''
    }
    $lastName = if ($null -ne $RawScheduleRecord.PSObject.Properties['customer_last_name'] -and -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.customer_last_name)) {
        ([string]$RawScheduleRecord.customer_last_name).Trim()
    } else {
        ''
    }
    $companyName = if ($null -ne $RawScheduleRecord.PSObject.Properties['company_name'] -and -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.company_name)) {
        ([string]$RawScheduleRecord.company_name).Trim()
    } else {
        ''
    }

    $contactName = ("$firstName $lastName").Trim()
    if (-not [string]::IsNullOrWhiteSpace($companyName)) {
        $contactName = if (-not [string]::IsNullOrWhiteSpace($contactName)) { "$contactName ($companyName)" } else { $companyName }
    }

    $eventNotes = ''
    if ($bookingType -eq 'Activity' -and -not [string]::IsNullOrWhiteSpace($sourceRef) -and $null -ne $ActivityDetailMap -and $ActivityDetailMap.ContainsKey($sourceRef)) {
        $actDetail = $ActivityDetailMap[$sourceRef]
        if ($null -ne $actDetail) {
            if ($null -ne $actDetail.PSObject.Properties['EventNotes'] -and -not [string]::IsNullOrWhiteSpace([string]$actDetail.EventNotes)) {
                $eventNotes = ([string]$actDetail.EventNotes).Trim()
            }
            if ([string]::IsNullOrWhiteSpace($contactName) -and $null -ne $actDetail.PSObject.Properties['Supervisor'] -and -not [string]::IsNullOrWhiteSpace([string]$actDetail.Supervisor)) {
                $contactName = ([string]$actDetail.Supervisor).Trim()
            }
        }
    }

    $notesSummaryForHash = @($eventNotes, $attendanceStr, $contactName, $eventTypeStr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $notesHashToken = ($notesSummaryForHash -join '|')

    # Authoritative status resolution
    $sourceStatus = 'Approved'
    if ($null -ne $RawScheduleRecord.PSObject.Properties['activity_status'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.activity_status)) {
        $sourceStatus = ([string]$RawScheduleRecord.activity_status).Trim()
    } elseif ($null -ne $RawScheduleRecord.PSObject.Properties['permit_status'] -and
        -not [string]::IsNullOrWhiteSpace([string]$RawScheduleRecord.permit_status)) {
        $sourceStatus = ([string]$RawScheduleRecord.permit_status).Trim()
    }

    $isSourceTentative = $sourceStatus -match '^(?i)(tentative|pending|hold|on\s*hold|stage)$'
    $isSourceCancelled = $sourceStatus -match '^(?i)(cancelled|canceled|withdrawn|deleted|retired|denied)$'

    $targetShowAs = if ($isSourceTentative) { 'tentative' } else { 'busy' }

    $segments = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Setup Event Segment (if setup_from_time is populated and SetupStart < EffectiveSetupEnd)
    $effectiveSetupEnd = if ($null -ne $setupEnd) { $setupEnd } else { $resStart }
    if ($null -ne $setupStart -and $setupStart -lt $effectiveSetupEnd) {
        $setupStartIso = Format-CentralIsoTimestamp -LocalDateTime $setupStart -TimeZone $TimeZone
        $setupEndIso   = Format-CentralIsoTimestamp -LocalDateTime $effectiveSetupEnd -TimeZone $TimeZone
        $setupBodyHtml = Format-EventBodyHtml `
            -SegmentType 'Setup' `
            -CleanTitle $cleanTitle `
            -BookingType $bookingType `
            -SourceRef $sourceRef `
            -EventType $eventTypeStr `
            -Attendance $attendanceStr `
            -ContactOrSupervisor $contactName `
            -EventNotes $eventNotes

        $setupFp = Get-EventSyncFingerprint `
            -CleanTitle 'Setup' `
            -EffectiveStartIso $setupStartIso `
            -EffectiveEndIso $setupEndIso `
            -IsSourceTentative $isSourceTentative `
            -NotesSummary $notesHashToken

        $segments.Add([PSCustomObject]@{
            SourceScheduleId      = "$sourceScheduleId`_SETUP"
            SegmentType           = 'Setup'
            BookingType           = $bookingType
            SourceReferenceNumber = $sourceRef
            FacilityId            = $facilityId
            FacilityName          = $facilityName
            ReservationStart      = $setupStart
            ReservationEnd        = $effectiveSetupEnd
            SetupStart            = $setupStart
            SetupEnd              = $effectiveSetupEnd
            TeardownStart         = $null
            TeardownEnd           = $null
            EffectiveStart        = $setupStart
            EffectiveEnd          = $effectiveSetupEnd
            EffectiveStartIso     = $setupStartIso
            EffectiveEndIso       = $setupEndIso
            RawEventName          = 'Setup'
            CleanTitle            = 'Setup'
            OutlookSubject        = 'Setup'
            EventNotes            = $eventNotes
            Attendance            = $attendanceStr
            ContactName           = $contactName
            BodyHtml              = $setupBodyHtml
            SourceStatus          = $sourceStatus
            IsSourceTentative     = [bool]$isSourceTentative
            IsSourceCancelled     = [bool]$isSourceCancelled
            SyncFingerprint       = $setupFp
            HasConflict           = $false
            ConflictDetails       = $null
            TargetShowAs          = $targetShowAs
        })
    }

    # 2. Main Reservation Event Segment
    $resStartIso = Format-CentralIsoTimestamp -LocalDateTime $resStart -TimeZone $TimeZone
    $resEndIso   = Format-CentralIsoTimestamp -LocalDateTime $resEnd -TimeZone $TimeZone

    $outlookSubject = if ($isSourceTentative) {
        "[Tentative] [AN] $cleanTitle"
    } else {
        "[AN] $cleanTitle"
    }

    $resBodyHtml = Format-EventBodyHtml `
        -SegmentType 'Reservation' `
        -CleanTitle $cleanTitle `
        -BookingType $bookingType `
        -SourceRef $sourceRef `
        -EventType $eventTypeStr `
        -Attendance $attendanceStr `
        -ContactOrSupervisor $contactName `
        -EventNotes $eventNotes

    $syncFingerprint = Get-EventSyncFingerprint `
        -CleanTitle $cleanTitle `
        -EffectiveStartIso $resStartIso `
        -EffectiveEndIso $resEndIso `
        -IsSourceTentative $isSourceTentative `
        -NotesSummary $notesHashToken

    $segments.Add([PSCustomObject]@{
        SourceScheduleId      = $sourceScheduleId
        SegmentType           = 'Reservation'
        BookingType           = $bookingType
        SourceReferenceNumber = $sourceRef
        FacilityId            = $facilityId
        FacilityName          = $facilityName
        ReservationStart      = $resStart
        ReservationEnd        = $resEnd
        SetupStart            = $setupStart
        SetupEnd              = $setupEnd
        TeardownStart         = $teardownStart
        TeardownEnd           = $teardownEnd
        EffectiveStart        = $resStart
        EffectiveEnd          = $resEnd
        EffectiveStartIso     = $resStartIso
        EffectiveEndIso       = $resEndIso
        RawEventName          = $rawEventName
        CleanTitle            = $cleanTitle
        OutlookSubject        = $outlookSubject
        EventNotes            = $eventNotes
        Attendance            = $attendanceStr
        ContactName           = $contactName
        BodyHtml              = $resBodyHtml
        SourceStatus          = $sourceStatus
        IsSourceTentative     = [bool]$isSourceTentative
        IsSourceCancelled     = [bool]$isSourceCancelled
        SyncFingerprint       = $syncFingerprint
        HasConflict           = $false
        ConflictDetails       = $null
        TargetShowAs          = $targetShowAs
    })

    # 3. Tear Down Event Segment (if tear_down_to_time is populated and EffectiveTeardownStart < TeardownEnd)
    $effectiveTeardownStart = if ($null -ne $teardownStart) { $teardownStart } else { $resEnd }
    if ($null -ne $teardownEnd -and $effectiveTeardownStart -lt $teardownEnd) {
        $tdStartIso = Format-CentralIsoTimestamp -LocalDateTime $effectiveTeardownStart -TimeZone $TimeZone
        $tdEndIso   = Format-CentralIsoTimestamp -LocalDateTime $teardownEnd -TimeZone $TimeZone
        $tdBodyHtml = Format-EventBodyHtml `
            -SegmentType 'Teardown' `
            -CleanTitle $cleanTitle `
            -BookingType $bookingType `
            -SourceRef $sourceRef `
            -EventType $eventTypeStr `
            -Attendance $attendanceStr `
            -ContactOrSupervisor $contactName `
            -EventNotes $eventNotes

        $tdFp = Get-EventSyncFingerprint `
            -CleanTitle 'Tear Down' `
            -EffectiveStartIso $tdStartIso `
            -EffectiveEndIso $tdEndIso `
            -IsSourceTentative $isSourceTentative `
            -NotesSummary $notesHashToken

        $segments.Add([PSCustomObject]@{
            SourceScheduleId      = "$sourceScheduleId`_TEARDOWN"
            SegmentType           = 'Teardown'
            BookingType           = $bookingType
            SourceReferenceNumber = $sourceRef
            FacilityId            = $facilityId
            FacilityName          = $facilityName
            ReservationStart      = $effectiveTeardownStart
            ReservationEnd        = $teardownEnd
            SetupStart            = $null
            SetupEnd              = $null
            TeardownStart         = $effectiveTeardownStart
            TeardownEnd           = $teardownEnd
            EffectiveStart        = $effectiveTeardownStart
            EffectiveEnd          = $teardownEnd
            EffectiveStartIso     = $tdStartIso
            EffectiveEndIso       = $tdEndIso
            RawEventName          = 'Tear Down'
            CleanTitle            = 'Tear Down'
            OutlookSubject        = 'Tear Down'
            EventNotes            = $eventNotes
            Attendance            = $attendanceStr
            ContactName           = $contactName
            BodyHtml              = $tdBodyHtml
            SourceStatus          = $sourceStatus
            IsSourceTentative     = [bool]$isSourceTentative
            IsSourceCancelled     = [bool]$isSourceCancelled
            SyncFingerprint       = $tdFp
            HasConflict           = $false
            ConflictDetails       = $null
            TargetShowAs          = $targetShowAs
        })
    }

    if ($segments.Count -eq 1) {
        return $segments[0]
    }
    return $segments.ToArray()
}

Export-ModuleMember -Function @(
    'Get-CentralTimeZoneInfo',
    'ConvertTo-CentralDateTimeOffset',
    'Format-CentralIsoTimestamp',
    'Get-EventSyncFingerprint',
    'Get-ActiveNetCompositeKey',
    'ConvertTo-NormalizedOccupancyEvent'
)
