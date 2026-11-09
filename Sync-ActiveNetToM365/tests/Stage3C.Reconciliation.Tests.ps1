#Requires -Version 7.0
Set-StrictMode -Version Latest

Describe 'Stage 3C: Reconciliation & Conflict Engine Unit Tests' {
    BeforeAll {
        $script:ModulesRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\src\modules'
        $script:SchemaPath  = Join-Path -Path $PSScriptRoot -ChildPath '..\state\state.schema.json'

        Import-Module (Join-Path $script:ModulesRoot 'EventModel.psm1') -Force
        Import-Module (Join-Path $script:ModulesRoot 'ConflictDetector.psm1') -Force
        Import-Module (Join-Path $script:ModulesRoot 'StateManager.psm1') -Force
        Import-Module (Join-Path $script:ModulesRoot 'ReconciliationEngine.psm1') -Force

        $script:MapiGuid      = '66f538b8-3e5e-4054-97c7-08051213f019'
        $script:PropSyncOwned = "String {$script:MapiGuid} Name ActiveNetSyncOwned"
        $script:PropSourceId  = "String {$script:MapiGuid} Name ActiveNetSourceId"

        function script:New-HealthyIntegrityRecord {
            return [PSCustomObject]@{
                pagesFetched  = 2
                pagesExpected = 2
                httpStatuses  = @(200, 200)
                codesSeen     = @('0000', '0000')
                isComplete    = $true
            }
        }

        function script:New-MockGraphEvent {
            param (
                [string]$Id,
                [string]$Subject,
                [string]$StartDateTime,
                [string]$EndDateTime,
                [string]$ShowAs = 'busy',
                [bool]$IsSyncOwned = $false,
                [string]$SourceScheduleId = '',
                [string]$ChangeKey = 'CK-001',
                [string]$OrganizerEmail = 'organizer@example.com',
                [bool]$IsCancelled = $false
            )

            $extProps = @()
            if ($IsSyncOwned) {
                $extProps = @(
                    [PSCustomObject]@{ id = $script:PropSyncOwned; value = 'True' },
                    [PSCustomObject]@{ id = $script:PropSourceId;  value = $SourceScheduleId }
                )
            }

            return [PSCustomObject]@{
                id                            = $Id
                subject                       = $Subject
                start                         = [PSCustomObject]@{ dateTime = $StartDateTime; timeZone = 'Central Standard Time' }
                end                           = [PSCustomObject]@{ dateTime = $EndDateTime;   timeZone = 'Central Standard Time' }
                showAs                        = $ShowAs
                isCancelled                   = $IsCancelled
                changeKey                     = $ChangeKey
                organizer                     = [PSCustomObject]@{
                    emailAddress = [PSCustomObject]@{
                        name    = 'Staff Organizer'
                        address = $OrganizerEmail
                    }
                }
                singleValueExtendedProperties = $extProps
            }
        }
    }

    Context 'EventModel.psm1 - Normalization, Setup/Teardown Fallback, Fingerprinting & DST' {
        It 'Builds Gate A Option A composite key and applies strict zero setup fallback when setup/teardown are null' {
            $rawPermit = [PSCustomObject]@{
                facility_id         = 440
                facility_name       = 'Conference Room A'
                start_date_time     = '2026-10-29 13:30:00'
                end_date_time       = '2026-10-29 14:30:00'
                setup_from_time     = $null
                setup_to_time       = $null
                tear_down_from_time = $null
                tear_down_to_time   = $null
                schedule_type_id    = 2
                schedule_type       = 'External Reservation'
                permit_number       = 34221
                permit_status       = 'Approved'
                event_description   = 'Manager Check-In'
                activity_number     = ''
                activity_name       = ''
                activity_status     = ''
            }

            $norm = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawPermit
            $norm.SourceScheduleId | Should -Be 'PERMIT_34221_2026-10-29 13:30:00'
            $norm.BookingType | Should -Be 'Permit'
            $norm.CleanTitle | Should -Be 'Manager Check-In'
            $norm.OutlookSubject | Should -Be '[AN] Manager Check-In'
            $norm.EffectiveStart | Should -Be ([datetime]'2026-10-29T13:30:00')
            $norm.EffectiveEnd | Should -Be ([datetime]'2026-10-29T14:30:00')
            $norm.TargetShowAs | Should -Be 'busy'
            $norm.SyncFingerprint | Should -Match '^[0-9a-f]{64}$'
        }

        It 'Emits three separate events (Setup, Main Event, Tear Down) and embeds event_notes and context when populated' {
            $rawActivity = [PSCustomObject]@{
                facility_id         = 440
                facility_name       = 'Conference Room A'
                start_date_time     = '2026-10-28 17:00:00'
                end_date_time       = '2026-10-28 20:00:00'
                setup_from_time     = '2026-10-28 16:45:00'
                setup_to_time       = '2026-10-28 17:00:00'
                tear_down_from_time = '2026-10-28 20:00:00'
                tear_down_to_time   = '2026-10-28 20:15:00'
                schedule_type_id    = 0
                schedule_type       = 'Standard Activity'
                event_type          = 'Class'
                attendance          = 10
                permit_number       = $null
                permit_status       = ''
                event_description   = ''
                activity_number     = '31033'
                activity_name       = 'Beginning Mahjong'
                activity_status     = 'Open'
            }

            $actDetails = @{
                '31033' = [PSCustomObject]@{
                    ActivityNumber = '31033'
                    ActivityId     = 25209
                    Supervisor     = 'Nancy Eschker'
                    EventNotes     = "4 chairs at each table`r`nchair for instructor`r`nset up as 2 card tables - move others to the side"
                    UserNotes      = ''
                }
            }

            $segments = @(ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawActivity -ActivityDetailMap $actDetails)
            $segments.Count | Should -Be 3

            # Segment 0: Setup
            $segments[0].SourceScheduleId | Should -Be 'ACT_31033_2026-10-28 17:00:00_SETUP'
            $segments[0].SegmentType | Should -Be 'Setup'
            $segments[0].OutlookSubject | Should -Be 'Setup'
            $segments[0].EffectiveStart | Should -Be ([datetime]'2026-10-28T16:45:00')
            $segments[0].EffectiveEnd | Should -Be ([datetime]'2026-10-28T17:00:00')
            $segments[0].EventNotes | Should -Match '4 chairs at each table'
            $segments[0].BodyHtml | Should -Match '4 chairs at each table'
            $segments[0].BodyHtml | Should -Match 'Nancy Eschker'

            # Segment 1: Main Reservation
            $segments[1].SourceScheduleId | Should -Be 'ACT_31033_2026-10-28 17:00:00'
            $segments[1].SegmentType | Should -Be 'Reservation'
            $segments[1].BookingType | Should -Be 'Activity'
            $segments[1].OutlookSubject | Should -Be '[AN] Beginning Mahjong'
            $segments[1].EffectiveStart | Should -Be ([datetime]'2026-10-28T17:00:00')
            $segments[1].EffectiveEnd | Should -Be ([datetime]'2026-10-28T20:00:00')
            $segments[1].BodyHtml | Should -Match '4 chairs at each table'
            $segments[1].BodyHtml | Should -Match 'Activity #31033'

            # Segment 2: Tear Down
            $segments[2].SourceScheduleId | Should -Be 'ACT_31033_2026-10-28 17:00:00_TEARDOWN'
            $segments[2].SegmentType | Should -Be 'Teardown'
            $segments[2].OutlookSubject | Should -Be 'Tear Down'
            $segments[2].EffectiveStart | Should -Be ([datetime]'2026-10-28T20:00:00')
            $segments[2].EffectiveEnd | Should -Be ([datetime]'2026-10-28T20:15:00')
            $segments[2].BodyHtml | Should -Match 'Tear Down for:'
        }

        It 'Embeds Permit operational context (Attendance, Contact Name, Permit Number, Event Type) into event body for non-activity permits' {
            $rawPermit = [PSCustomObject]@{
                facility_id         = 440
                facility_name       = 'Conference Room A'
                start_date_time     = '2026-10-29 13:30:00'
                end_date_time       = '2026-10-29 14:30:00'
                setup_from_time     = '2026-10-29 13:15:00'
                setup_to_time       = '2026-10-29 13:30:00'
                tear_down_from_time = '2026-10-29 14:30:00'
                tear_down_to_time   = '2026-10-29 14:45:00'
                schedule_type_id    = 2
                schedule_type       = 'External Reservation'
                event_type          = 'Meeting'
                event_description   = 'Internal - NBPD Safety Committee Meeting - J Kinsland'
                attendance          = 12
                permit_status       = 'Approved'
                permit_number       = 34221
                customer_first_name = 'Jesse'
                customer_last_name  = 'Kinsland'
            }

            $segments = @(ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawPermit)
            $segments.Count | Should -Be 3
            $segments[0].BodyHtml | Should -Match 'Permit #34221'
            $segments[0].BodyHtml | Should -Match 'Jesse Kinsland'
            $segments[0].BodyHtml | Should -Match '12'
            $segments[1].BodyHtml | Should -Match 'Meeting'
        }

        It 'Formats tentative reservations with [Tentative] [AN] subject and tentative showAs' {
            $rawTentative = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-10 09:00:00'
                end_date_time     = '2026-11-10 10:00:00'
                permit_number     = 55100
                permit_status     = 'Tentative'
                event_description = 'Committee Planning'
            }

            $norm = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawTentative
            $norm.IsSourceTentative | Should -BeTrue
            $norm.OutlookSubject | Should -Be '[Tentative] [AN] Committee Planning'
            $norm.TargetShowAs | Should -Be 'tentative'
        }

        It 'Correctly computes America/Chicago UTC offsets across Spring Forward (2026-03-08) and Fall Back (2026-11-01) DST transitions' {
            # Second Sunday in March 2026: 2026-03-08 (CST -06:00 -> CDT -05:00)
            $beforeSpringIso = Format-CentralIsoTimestamp -LocalDateTime ([datetime]'2026-03-08T01:00:00')
            $afterSpringIso  = Format-CentralIsoTimestamp -LocalDateTime ([datetime]'2026-03-08T10:00:00')
            $gapSpringIso    = Format-CentralIsoTimestamp -LocalDateTime ([datetime]'2026-03-08T02:30:00')

            $beforeSpringIso | Should -Be '2026-03-08T01:00:00-06:00'
            $afterSpringIso  | Should -Be '2026-03-08T10:00:00-05:00'
            $gapSpringIso    | Should -Be '2026-03-08T03:30:00-05:00'

            # First Sunday in November 2026: 2026-11-01 (CDT -05:00 -> CST -06:00)
            $beforeFallIso = Format-CentralIsoTimestamp -LocalDateTime ([datetime]'2026-11-01T00:30:00')
            $afterFallIso  = Format-CentralIsoTimestamp -LocalDateTime ([datetime]'2026-11-01T10:00:00')

            $beforeFallIso | Should -Be '2026-11-01T00:30:00-05:00'
            $afterFallIso  | Should -Be '2026-11-01T10:00:00-06:00'
        }
    }

    Context 'ConflictDetector.psm1 - Half-Open Interval [Start, End) & Conflict Identity' {
        It 'Treats abutting boundary intervals (10:00-11:00 and 11:00-12:00) as non-conflicting' {
            $sA = [datetime]'2026-11-15T10:00:00'
            $eA = [datetime]'2026-11-15T11:00:00'
            $sB = [datetime]'2026-11-15T11:00:00'
            $eB = [datetime]'2026-11-15T12:00:00'

            (Test-IntervalOverlap -StartA $sA -EndA $eA -StartB $sB -EndB $eB) | Should -BeFalse
            (Test-IntervalOverlap -StartA $sB -EndA $eB -StartB $sA -EndB $eA) | Should -BeFalse
        }

        It 'Detects partial, enclosing, and setup-segment overlaps against Outlook-native meetings while ignoring cancelled/sync-owned events' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-15 10:00:00'
                end_date_time     = '2026-11-15 11:00:00'
                setup_from_time   = '2026-11-15 09:45:00'
                setup_to_time     = '2026-11-15 10:00:00'
                permit_number     = 40001
                permit_status     = 'Approved'
                event_description = 'Board Prep'
            }
            $segments = @(ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn)
            $setupEv = $segments[0]
            $mainEv  = $segments[1]

            $abuttingOutlook = New-MockGraphEvent -Id 'OUT-ABUT' -Subject 'Prior Meeting' -StartDateTime '2026-11-15T09:00:00' -EndDateTime '2026-11-15T09:45:00'
            $setupOverlapOutlook = New-MockGraphEvent -Id 'OUT-OVERLAP' -Subject 'Overrunning Meeting' -StartDateTime '2026-11-15T09:00:00' -EndDateTime '2026-11-15T10:00:00' -ChangeKey 'CK-77'
            $cancelledOutlook = New-MockGraphEvent -Id 'OUT-CANCELLED' -Subject 'Cancelled Meeting' -StartDateTime '2026-11-15T10:00:00' -EndDateTime '2026-11-15T11:00:00' -IsCancelled $true
            $syncOwnedEvent = New-MockGraphEvent -Id 'SYNC-1' -Subject '[AN] Other Synced' -StartDateTime '2026-11-15T10:00:00' -EndDateTime '2026-11-15T11:00:00' -IsSyncOwned $true -SourceScheduleId 'PERMIT_40001_2026-11-15 10:00:00'

            $setupConflicts = @(Find-CalendarConflict -NormalizedEvent $setupEv -OutlookNativeEvents @($abuttingOutlook, $setupOverlapOutlook, $cancelledOutlook, $syncOwnedEvent))
            $setupConflicts.Count | Should -Be 1
            $setupConflicts[0].OutlookEventId | Should -Be 'OUT-OVERLAP'
            $setupConflicts[0].OutlookChangeKey | Should -Be 'CK-77'
            $setupConflicts[0].ConflictKey | Should -Match '^[0-9a-f]{64}$'

            $mainConflicts = @(Find-CalendarConflict -NormalizedEvent $mainEv -OutlookNativeEvents @($abuttingOutlook, $setupOverlapOutlook, $cancelledOutlook, $syncOwnedEvent))
            $mainConflicts.Count | Should -Be 0
        }
    }

    Context 'StateManager.psm1 - Missing State, Corrupt State Abort, and Atomic Persistence' {
        BeforeEach {
            $script:TestStateDir = Join-Path -Path $TestDrive -ChildPath "state-$([guid]::NewGuid().ToString('N'))"
            [void](New-Item -Path $script:TestStateDir -ItemType Directory -Force)
            $script:TestStateFile = Join-Path -Path $script:TestStateDir -ChildPath 'sync_state.json'
        }

        It 'Scenario 5 (State): Enters ReconstructOnly mode with IsMissing = $true when state file does not exist' {
            $state = Get-SyncState -StateFilePath $script:TestStateFile
            $state.IsMissing | Should -BeTrue
            $state.Mode | Should -Be 'ReconstructOnly'
            $state.Records.Count | Should -Be 0
        }

        It 'Scenario 6 (State): Aborts immediately with fatal error when state file is malformed JSON or violates schema' {
            Set-Content -LiteralPath $script:TestStateFile -Value '{ "schemaVersion": "1.0.0", "records": { BROKEN JSON ' -Encoding utf8
            { Get-SyncState -StateFilePath $script:TestStateFile } | Should -Throw '*FATAL STATE CORRUPTION*'

            Set-Content -LiteralPath $script:TestStateFile -Value '{ "schemaVersion": "9.9.9" }' -Encoding utf8
            { Get-SyncState -StateFilePath $script:TestStateFile } | Should -Throw '*FATAL STATE CORRUPTION*'
        }

        It 'Atomically writes state via .tmp, validates against state.schema.json, and creates .bak on overwrite' {
            $initialState = @{
                schemaVersion              = '1.0.0'
                lastRunId                  = '11111111-2222-3333-4444-555555555555'
                lastSuccessfulRunTimestamp = '2026-10-26T07:00:00Z'
                facilityId                 = 440
                facilityName               = 'Conference Room A'
                records                    = @{
                    'PERMIT_34221_2026-10-29 13:30:00' = @{
                        sourceScheduleId    = 'PERMIT_34221_2026-10-29 13:30:00'
                        graphEventId        = 'GRAPH-EV-01'
                        syncFingerprint     = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
                        effectiveStart      = '2026-10-29T13:30:00-05:00'
                        effectiveEnd        = '2026-10-29T14:30:00-05:00'
                        sourceStatus        = 'Approved'
                        lastSynchronizedUtc = '2026-10-26T07:00:00Z'
                        activeConflict      = $null
                    }
                }
            }

            Save-SyncStateAtomic -StateData $initialState -StateFilePath $script:TestStateFile -SchemaFilePath $script:SchemaPath
            (Test-Path -LiteralPath $script:TestStateFile) | Should -BeTrue
            (Test-Path -LiteralPath "$($script:TestStateFile).tmp") | Should -BeFalse

            # Second write should create .bak
            $initialState.lastRunId = '99999999-8888-7777-6666-555555555555'
            Save-SyncStateAtomic -StateData $initialState -StateFilePath $script:TestStateFile -SchemaFilePath $script:SchemaPath
            (Test-Path -LiteralPath "$($script:TestStateFile).bak") | Should -BeTrue

            $loaded = Get-SyncState -StateFilePath $script:TestStateFile -SchemaFilePath $script:SchemaPath
            $loaded.IsMissing | Should -BeFalse
            $loaded.Mode | Should -Be 'Normal'
            $loaded.LastRunId | Should -Be '99999999-8888-7777-6666-555555555555'
            $loaded.Records.ContainsKey('PERMIT_34221_2026-10-29 13:30:00') | Should -BeTrue
        }
    }

    Context 'ReconciliationEngine.psm1 - Ownership Safety Proof (All 7 Section 9 Scenarios)' {
        It 'Scenario 1: Unrelated Outlook meeting is never modified or deleted (OutlookNativeModified == 0)' {
            $unrelatedMeeting = New-MockGraphEvent -Id 'OUT-UNRELATED-1' -Subject 'Weekly Budget Review' -StartDateTime '2026-10-30T09:00:00' -EndDateTime '2026-10-30T10:00:00'
            $integrity = New-HealthyIntegrityRecord

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($unrelatedMeeting) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = @{} } `
                -SourceIntegrityRecord $integrity

            $result.Summary.OutlookNativeInspected | Should -Be 1
            $result.Summary.OutlookNativeModified | Should -Be 0
            $result.Summary.Deleted | Should -Be 0
            $result.Summary.Updated | Should -Be 0
            $result.PlanItems.Count | Should -Be 0
        }

        It 'Scenario 2: Outlook meeting with same subject as ACTIVENet booking is treated as Outlook-native and never touched' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-02 18:00:00'
                end_date_time     = '2026-11-02 20:00:00'
                permit_number     = 50001
                permit_status     = 'Approved'
                event_description = 'Board of Commissioners'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn
            $sameSubjectOutlook = New-MockGraphEvent -Id 'OUT-SAME-SUBJ' -Subject 'Board of Commissioners' -StartDateTime '2026-11-02T18:30:00' -EndDateTime '2026-11-02T19:30:00'

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($sameSubjectOutlook) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = @{} } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $result.Summary.OutlookNativeInspected | Should -Be 1
            $result.Summary.OutlookNativeModified | Should -Be 0
            $result.Summary.Created | Should -Be 1
            $result.Summary.ConflictsDetected | Should -Be 1
            $normEv.TargetShowAs | Should -Be 'tentative'
            @($result.PlanItems | Where-Object { $_.Action -in @('UPDATE', 'DELETE') -and $_.TargetGraphEventId -eq 'OUT-SAME-SUBJ' }).Count | Should -Be 0
        }

        It 'Scenario 3: Outlook meeting with identical subject, time, and location is bypassed for mutations and creates distinct projection' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-03 14:00:00'
                end_date_time     = '2026-11-03 15:00:00'
                permit_number     = 50002
                permit_status     = 'Approved'
                event_description = 'Staff Leadership Sync'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn
            $identicalOutlook = New-MockGraphEvent -Id 'OUT-IDENTICAL' -Subject 'Staff Leadership Sync' -StartDateTime '2026-11-03T14:00:00' -EndDateTime '2026-11-03T15:00:00'

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($identicalOutlook) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = @{} } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $result.Summary.OutlookNativeInspected | Should -Be 1
            $result.Summary.OutlookNativeModified | Should -Be 0
            $result.Summary.Created | Should -Be 1
            $result.Summary.ConflictsDetected | Should -Be 1
            @($result.PlanItems | Where-Object { $_.Action -in @('UPDATE', 'DELETE') }).Count | Should -Be 0
        }

        It 'Scenario 4: User manually titles Outlook meeting "[AN] Team Huddle" without MAPI property -> treated as Outlook-native and untouched' {
            $spoofedOutlook = New-MockGraphEvent -Id 'OUT-SPOOFED-AN' -Subject '[AN] Team Huddle' -StartDateTime '2026-11-04T10:00:00' -EndDateTime '2026-11-04T11:00:00' -IsSyncOwned $false

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($spoofedOutlook) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = @{} } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $result.Summary.OutlookNativeInspected | Should -Be 1
            $result.Summary.OutlookNativeModified | Should -Be 0
            $result.Summary.Deleted | Should -Be 0
            $result.PlanItems.Count | Should -Be 0
        }

        It 'Scenario 5: Missing local JSON state enters ReconstructOnly mode, correlates MAPI-tagged events, and produces 0 DELETE actions' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-05 09:00:00'
                end_date_time     = '2026-11-05 10:00:00'
                permit_number     = 60001
                permit_status     = 'Approved'
                event_description = 'Existing Synced Booking'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn

            # Existing calendar has one matching MAPI-tagged event, one orphaned MAPI-tagged event, and one Outlook-native event
            $matchingTagged = New-MockGraphEvent -Id 'G-MATCH' -Subject '[AN] Existing Synced Booking' -StartDateTime '2026-11-05T09:00:00' -EndDateTime '2026-11-05T10:00:00' -IsSyncOwned $true -SourceScheduleId $normEv.SourceScheduleId
            $orphanedTagged = New-MockGraphEvent -Id 'G-ORPHAN' -Subject '[AN] Cancelled Old Booking' -StartDateTime '2026-11-06T09:00:00' -EndDateTime '2026-11-06T10:00:00' -IsSyncOwned $true -SourceScheduleId 'PERMIT_99999_2026-11-06 09:00:00'
            $nativeMeeting  = New-MockGraphEvent -Id 'G-NATIVE' -Subject 'HR Interview' -StartDateTime '2026-11-07T09:00:00' -EndDateTime '2026-11-07T10:00:00' -IsSyncOwned $false

            $missingStateObj = [PSCustomObject]@{
                IsMissing = $true
                Mode      = 'ReconstructOnly'
                Records   = @{}
            }

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($matchingTagged, $orphanedTagged, $nativeMeeting) `
                -StateObject $missingStateObj `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $result.CircuitBreaker.CanDelete | Should -BeFalse
            $result.CircuitBreaker.StatePresenceGatePassed | Should -BeFalse
            $result.Summary.Deleted | Should -Be 0
            $result.Summary.Created | Should -Be 0
            $result.Summary.OutlookNativeModified | Should -Be 0
            @($result.PlanItems | Where-Object { $_.Action -eq 'DELETE' }).Count | Should -Be 0
        }

        It 'Scenario 7a & 7b: Stale or recycled Graph ID triggers RECREATE when active and refuses DELETE when MAPI verification fails' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-08 13:00:00'
                end_date_time     = '2026-11-08 14:00:00'
                permit_number     = 70001
                permit_status     = 'Approved'
                event_description = 'Recycled ID Test'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn

            $stateRecords = @{
                $normEv.SourceScheduleId = @{
                    sourceScheduleId    = $normEv.SourceScheduleId
                    graphEventId        = 'E-123-STALE'
                    syncFingerprint     = $normEv.SyncFingerprint
                    effectiveStart      = $normEv.EffectiveStartIso
                    effectiveEnd        = $normEv.EffectiveEndIso
                    sourceStatus        = 'Approved'
                    lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                    activeConflict      = $null
                }
                'PERMIT_70002_2026-11-09 10:00:00' = @{
                    sourceScheduleId    = 'PERMIT_70002_2026-11-09 10:00:00'
                    graphEventId        = 'E-456-HIJACKED'
                    syncFingerprint     = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
                    effectiveStart      = '2026-11-09T10:00:00-06:00'
                    effectiveEnd        = '2026-11-09T11:00:00-06:00'
                    sourceStatus        = 'Approved'
                    lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                    activeConflict      = $null
                }
            }

            # E-456-HIJACKED exists on calendar, but lacks MAPI ownership properties!
            $recycledUntaggedEvent = New-MockGraphEvent -Id 'E-456-HIJACKED' -Subject 'External Meeting Using Recycled ID' -StartDateTime '2026-11-09T10:00:00' -EndDateTime '2026-11-09T11:00:00' -IsSyncOwned $false

            $result = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($recycledUntaggedEvent) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = $stateRecords } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            # E-123-STALE is missing from calendar -> RECREATE
            $result.Summary.Recreated | Should -Be 1
            @($result.PlanItems | Where-Object { $_.Action -eq 'RECREATE' -and $_.SourceScheduleId -eq $normEv.SourceScheduleId }).Count | Should -Be 1

            # E-456-HIJACKED fails MAPI check -> NEVER deleted!
            $result.Summary.Deleted | Should -Be 0
            $result.Summary.OutlookNativeModified | Should -Be 0
            @($result.PlanItems | Where-Object { $_.Action -eq 'DELETE' }).Count | Should -Be 0
        }
    }

    Context 'ReconciliationEngine.psm1 - Destructive Operation Circuit Breaker Gates (Section 10.2)' {
        BeforeEach {
            $script:StaleScheduleId = 'PERMIT_80001_2026-11-12 10:00:00'
            $script:SyncedGraphEv = New-MockGraphEvent `
                -Id 'G-SYNC-80001' `
                -Subject '[AN] Cancelled Workshop' `
                -StartDateTime '2026-11-12T10:00:00' `
                -EndDateTime '2026-11-12T11:00:00' `
                -IsSyncOwned $true `
                -SourceScheduleId $script:StaleScheduleId

            $script:SingleRecordState = @{
                IsMissing = $false
                Mode      = 'Normal'
                Records   = @{
                    $script:StaleScheduleId = @{
                        sourceScheduleId    = $script:StaleScheduleId
                        graphEventId        = 'G-SYNC-80001'
                        syncFingerprint     = '1111111111111111111111111111111111111111111111111111111111111111'
                        effectiveStart      = '2026-11-12T10:00:00-06:00'
                        effectiveEnd        = '2026-11-12T11:00:00-06:00'
                        sourceStatus        = 'Approved'
                        lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                        activeConflict      = $null
                    }
                }
            }
        }

        It 'Gate 1 (HTTP Success): Suppresses DELETE when any HTTP status is not 200' {
            $badHttpIntegrity = [PSCustomObject]@{
                pagesFetched  = 2
                pagesExpected = 2
                httpStatuses  = @(200, 503)
                codesSeen     = @('0000', '0000')
                isComplete    = $true
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($script:SyncedGraphEv) `
                -StateObject $script:SingleRecordState `
                -SourceIntegrityRecord $badHttpIntegrity

            $res.CircuitBreaker.HttpSuccessGatePassed | Should -BeFalse
            $res.CircuitBreaker.CanDelete | Should -BeFalse
            $res.Summary.Deleted | Should -Be 0
            $res.Summary.SuppressedDeletesCount | Should -Be 1
        }

        It 'Gate 2 (API Response Code): Suppresses DELETE when any ACTIVENet response_code is outside (0000, 0001)' {
            $badCodeIntegrity = [PSCustomObject]@{
                pagesFetched  = 1
                pagesExpected = 1
                httpStatuses  = @(200)
                codesSeen     = @('0013')
                isComplete    = $true
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($script:SyncedGraphEv) `
                -StateObject $script:SingleRecordState `
                -SourceIntegrityRecord $badCodeIntegrity

            $res.CircuitBreaker.ResponseCodeGatePassed | Should -BeFalse
            $res.CircuitBreaker.CanDelete | Should -BeFalse
            $res.Summary.Deleted | Should -Be 0
            $res.Summary.SuppressedDeletesCount | Should -Be 1
        }

        It 'Gate 3 (Pagination Integrity): Suppresses DELETE when isComplete is false or pagesFetched != pagesExpected' {
            $incompletePagination = [PSCustomObject]@{
                pagesFetched  = 1
                pagesExpected = 3
                httpStatuses  = @(200)
                codesSeen     = @('0000')
                isComplete    = $false
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($script:SyncedGraphEv) `
                -StateObject $script:SingleRecordState `
                -SourceIntegrityRecord $incompletePagination

            $res.CircuitBreaker.PaginationGatePassed | Should -BeFalse
            $res.CircuitBreaker.CanDelete | Should -BeFalse
            $res.Summary.Deleted | Should -Be 0
            $res.Summary.SuppressedDeletesCount | Should -Be 1
        }

        It 'Gate 4 (Volume Anomaly): Suppresses DELETE when previous state had >10 records and current retrieval returns 0' {
            $twelveRecords = @{}
            $twelveCalEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
            for ($i = 1; $i -le 12; $i++) {
                $k = "PERMIT_900$i`_2026-11-15 10:00:00"
                $gId = "G-VOL-$i"
                $twelveRecords[$k] = @{
                    sourceScheduleId    = $k
                    graphEventId        = $gId
                    syncFingerprint     = '2222222222222222222222222222222222222222222222222222222222222222'
                    effectiveStart      = '2026-11-15T10:00:00-06:00'
                    effectiveEnd        = '2026-11-15T11:00:00-06:00'
                    sourceStatus        = 'Approved'
                    lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                    activeConflict      = $null
                }
                $twelveCalEvents.Add((New-MockGraphEvent -Id $gId -Subject "[AN] Event $i" -StartDateTime '2026-11-15T10:00:00' -EndDateTime '2026-11-15T11:00:00' -IsSyncOwned $true -SourceScheduleId $k))
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents ($twelveCalEvents.ToArray()) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = $twelveRecords } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $res.CircuitBreaker.VolumeAnomalyGatePassed | Should -BeFalse
            $res.CircuitBreaker.CanDelete | Should -BeFalse
            $res.Summary.Deleted | Should -Be 0
            $res.Summary.SuppressedDeletesCount | Should -Be 12
        }

        It 'Permits DELETE when all Circuit Breaker gates pass and target event passes MAPI ownership verification' {
            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @() `
                -CalendarEvents @($script:SyncedGraphEv) `
                -StateObject $script:SingleRecordState `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $res.CircuitBreaker.CanDelete | Should -BeTrue
            $res.Summary.Deleted | Should -Be 1
            $res.PlanItems[0].Action | Should -Be 'DELETE'
            $res.PlanItems[0].TargetGraphEventId | Should -Be 'G-SYNC-80001'
        }
    }

    Context 'Idempotency, Tamper Recovery, and Conflict Notification Deduplication Lifecycle' {
        It 'Guarantees idempotency (0 CREATE, 0 UPDATE, 0 DELETE, all UNCHANGED) on repeated runs with identical inputs' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-20 13:00:00'
                end_date_time     = '2026-11-20 15:00:00'
                permit_number     = 88001
                permit_status     = 'Approved'
                event_description = 'Idempotent Seminar'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn

            $calEv = New-MockGraphEvent `
                -Id 'G-IDEM-1' `
                -Subject $normEv.OutlookSubject `
                -StartDateTime '2026-11-20T13:00:00' `
                -EndDateTime '2026-11-20T15:00:00' `
                -ShowAs 'busy' `
                -IsSyncOwned $true `
                -SourceScheduleId $normEv.SourceScheduleId

            $stateObj = @{
                IsMissing = $false
                Mode      = 'Normal'
                Records   = @{
                    $normEv.SourceScheduleId = @{
                        sourceScheduleId    = $normEv.SourceScheduleId
                        graphEventId        = 'G-IDEM-1'
                        syncFingerprint     = $normEv.SyncFingerprint
                        effectiveStart      = $normEv.EffectiveStartIso
                        effectiveEnd        = $normEv.EffectiveEndIso
                        sourceStatus        = $normEv.SourceStatus
                        lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                        activeConflict      = $null
                    }
                }
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($calEv) `
                -StateObject $stateObj `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $res.Summary.Created | Should -Be 0
            $res.Summary.Updated | Should -Be 0
            $res.Summary.Recreated | Should -Be 0
            $res.Summary.Deleted | Should -Be 0
            $res.Summary.Unchanged | Should -Be 1
            $res.PlanItems[0].Action | Should -Be 'UNCHANGED'
        }

        It 'Detects manual Outlook tampering on a synced event and classifies as UPDATE to restore authoritative truth' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-21 09:00:00'
                end_date_time     = '2026-11-21 11:00:00'
                permit_number     = 88002
                permit_status     = 'Approved'
                event_description = 'Authoritative Title'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn

            # Someone manually edited the subject in Outlook even though SyncFingerprint in state hasn't changed
            $tamperedCalEv = New-MockGraphEvent `
                -Id 'G-TAMPER-1' `
                -Subject '[AN] Tampered By User' `
                -StartDateTime '2026-11-21T09:00:00' `
                -EndDateTime '2026-11-21T11:00:00' `
                -ShowAs 'busy' `
                -IsSyncOwned $true `
                -SourceScheduleId $normEv.SourceScheduleId

            $stateObj = @{
                IsMissing = $false
                Mode      = 'Normal'
                Records   = @{
                    $normEv.SourceScheduleId = @{
                        sourceScheduleId    = $normEv.SourceScheduleId
                        graphEventId        = 'G-TAMPER-1'
                        syncFingerprint     = $normEv.SyncFingerprint
                        effectiveStart      = $normEv.EffectiveStartIso
                        effectiveEnd        = $normEv.EffectiveEndIso
                        sourceStatus        = $normEv.SourceStatus
                        lastSynchronizedUtc = '2026-10-26T02:00:00Z'
                        activeConflict      = $null
                    }
                }
            }

            $res = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($tamperedCalEv) `
                -StateObject $stateObj `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $res.Summary.Updated | Should -Be 1
            $res.PlanItems[0].Action | Should -Be 'UPDATE'
        }

        It 'Deduplicates conflict NOTIFY decisions across runs, re-notifies on ChangeKey update, and clears on resolution' {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-22 10:00:00'
                end_date_time     = '2026-11-22 12:00:00'
                permit_number     = 88003
                permit_status     = 'Approved'
                event_description = 'Parks Foundation Meeting'
            }
            $normEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn
            $syncedCalEv = New-MockGraphEvent -Id 'G-SYNC-88003' -Subject $normEv.OutlookSubject -StartDateTime '2026-11-22T10:00:00' -EndDateTime '2026-11-22T12:00:00' -ShowAs 'tentative' -IsSyncOwned $true -SourceScheduleId $normEv.SourceScheduleId
            $outlookConflictEv = New-MockGraphEvent -Id 'OUT-CONF-1' -Subject 'Staff Training' -StartDateTime '2026-11-22T11:00:00' -EndDateTime '2026-11-22T13:00:00' -ChangeKey 'CK-INITIAL'

            # Run 1: First detection -> emits NOTIFY
            $run1 = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($syncedCalEv, $outlookConflictEv) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = @{} } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $run1.Summary.ConflictsDetected | Should -Be 1
            $run1.Summary.NotificationsDispatched | Should -Be 1
            $run1.Summary.NotificationsSuppressed | Should -Be 0

            # Simulate state persisted after Run 1 with real Graph ID
            $stateAfterRun1 = $run1.NextStateRecords
            $stateAfterRun1[$normEv.SourceScheduleId]['graphEventId'] = 'G-SYNC-88003'

            # Run 2: Identical conflict & ChangeKey -> suppresses duplicate NOTIFY
            $run2 = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($syncedCalEv, $outlookConflictEv) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = $stateAfterRun1 } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $run2.Summary.ConflictsDetected | Should -Be 1
            $run2.Summary.NotificationsDispatched | Should -Be 0
            $run2.Summary.NotificationsSuppressed | Should -Be 1
            @($run2.PlanItems | Where-Object { $_.Action -eq 'NOTIFY' }).Count | Should -Be 0

            # Run 3: Outlook meeting ChangeKey changes -> emits new NOTIFY
            $outlookConflictEvModified = New-MockGraphEvent -Id 'OUT-CONF-1' -Subject 'Staff Training Rescheduled' -StartDateTime '2026-11-22T11:30:00' -EndDateTime '2026-11-22T13:00:00' -ChangeKey 'CK-UPDATED'
            $run3 = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($syncedCalEv, $outlookConflictEvModified) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = $run2.NextStateRecords } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $run3.Summary.NotificationsDispatched | Should -Be 1

            # Run 4: Conflict resolved (Outlook meeting removed) -> clears activeConflict and updates showAs back to busy
            $run4 = Invoke-ReconciliationDiff `
                -NormalizedSourceEvents @($normEv) `
                -CalendarEvents @($syncedCalEv) `
                -StateObject @{ IsMissing = $false; Mode = 'Normal'; Records = $run3.NextStateRecords } `
                -SourceIntegrityRecord (New-HealthyIntegrityRecord)

            $run4.Summary.ConflictsDetected | Should -Be 0
            $run4.Summary.Updated | Should -Be 1
            $run4.NextStateRecords[$normEv.SourceScheduleId]['activeConflict'] | Should -BeNullOrEmpty
            $normEv.TargetShowAs | Should -Be 'busy'
        }
    }
}
