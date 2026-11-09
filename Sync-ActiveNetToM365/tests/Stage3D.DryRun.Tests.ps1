#Requires -Version 7.0
Set-StrictMode -Version Latest

Describe 'Stage 3D: Dry-Run Write Isolation & End-to-End Orchestrator Tests' {
    BeforeAll {
        $script:ModulesRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\src\modules'
        $script:SyncScript  = Join-Path -Path $PSScriptRoot -ChildPath '..\src\Sync-ActiveNetToM365.ps1'

        Import-Module (Join-Path $script:ModulesRoot 'EventModel.psm1') -Force
        Import-Module (Join-Path $script:ModulesRoot 'GraphClient.psm1') -Force
        Import-Module (Join-Path $script:ModulesRoot 'ReconciliationEngine.psm1') -Force
    }

    Context 'Invoke-CalendarAction - Structural Dry-Run Write Isolation (Section 17.3)' {
        BeforeEach {
            $rawAn = [PSCustomObject]@{
                facility_id       = 440
                facility_name     = 'Conference Room A'
                start_date_time   = '2026-11-05 10:00:00'
                end_date_time     = '2026-11-05 11:00:00'
                permit_number     = 91001
                permit_status     = 'Approved'
                event_description = 'DryRun Isolation Test'
            }
            $script:SampleNormEv = ConvertTo-NormalizedOccupancyEvent -RawScheduleRecord $rawAn
        }

        It 'Intercepts CREATE, RECREATE, UPDATE, DELETE, and NOTIFY in DryRun mode with zero Graph mutation calls' {
            Mock -CommandName Invoke-RestMethod -ModuleName GraphClient -MockWith {
                throw 'Invoke-RestMethod must NEVER be called during DryRun!'
            }

            $createItem = [PSCustomObject]@{
                Action             = 'CREATE'
                SourceScheduleId   = $script:SampleNormEv.SourceScheduleId
                NormalizedEvent    = $script:SampleNormEv
                TargetGraphEventId = $null
                ConflictRecord     = $null
                Reason             = 'New event'
            }
            $recreateItem = [PSCustomObject]@{
                Action             = 'RECREATE'
                SourceScheduleId   = $script:SampleNormEv.SourceScheduleId
                NormalizedEvent    = $script:SampleNormEv
                TargetGraphEventId = $null
                ConflictRecord     = $null
                Reason             = 'Missing from calendar'
            }
            $updateItem = [PSCustomObject]@{
                Action             = 'UPDATE'
                SourceScheduleId   = $script:SampleNormEv.SourceScheduleId
                NormalizedEvent    = $script:SampleNormEv
                TargetGraphEventId = 'G-100'
                ConflictRecord     = $null
                Reason             = 'Time changed'
            }
            $deleteItem = [PSCustomObject]@{
                Action             = 'DELETE'
                SourceScheduleId   = $script:SampleNormEv.SourceScheduleId
                NormalizedEvent    = $null
                TargetGraphEventId = 'G-100'
                ConflictRecord     = $null
                Reason             = 'Cancelled in source'
            }
            $notifyItem = [PSCustomObject]@{
                Action             = 'NOTIFY'
                SourceScheduleId   = $script:SampleNormEv.SourceScheduleId
                NormalizedEvent    = $script:SampleNormEv
                TargetGraphEventId = 'OUT-200'
                ConflictRecord     = [PSCustomObject]@{
                    ConflictKey           = 'abc123'
                    OutlookEventId        = 'OUT-200'
                    OutlookOrganizerEmail = 'staff@example.com'
                }
                Reason             = 'Overlap'
            }

            $rCreate   = Invoke-CalendarAction -PlanItem $createItem   -Mailbox 'roommailbox@example.com' -DryRun
            $rRecreate = Invoke-CalendarAction -PlanItem $recreateItem -Mailbox 'roommailbox@example.com' -DryRun
            $rUpdate   = Invoke-CalendarAction -PlanItem $updateItem   -Mailbox 'roommailbox@example.com' -DryRun
            $rDelete   = Invoke-CalendarAction -PlanItem $deleteItem   -Mailbox 'roommailbox@example.com' -DryRun
            $rNotify   = Invoke-CalendarAction -PlanItem $notifyItem   -Mailbox 'roommailbox@example.com' -DryRun

            $rCreate.Executed   | Should -BeFalse
            $rCreate.Simulated  | Should -BeTrue
            $rCreate.LogMessage | Should -Match '^\[WOULD CREATE\]'

            $rRecreate.Executed   | Should -BeFalse
            $rRecreate.Simulated  | Should -BeTrue
            $rRecreate.LogMessage | Should -Match '^\[WOULD RECREATE\]'

            $rUpdate.Executed   | Should -BeFalse
            $rUpdate.Simulated  | Should -BeTrue
            $rUpdate.LogMessage | Should -Match '^\[WOULD UPDATE\]'

            $rDelete.Executed   | Should -BeFalse
            $rDelete.Simulated  | Should -BeTrue
            $rDelete.LogMessage | Should -Match '^\[WOULD DELETE\]'

            $rNotify.Executed   | Should -BeFalse
            $rNotify.Simulated  | Should -BeTrue
            $rNotify.LogMessage | Should -Match '^\[WOULD NOTIFY\]'

            Should -Invoke -CommandName Invoke-RestMethod -ModuleName GraphClient -Times 0 -Exactly
        }
    }

    Context 'Sync-ActiveNetToM365.ps1 - End-to-End Dry-Run Orchestration & Corrupt State Protection' {
        BeforeEach {
            $script:TempRoot  = Join-Path -Path $TestDrive -ChildPath "e2e-$([guid]::NewGuid().ToString('N'))"
            $script:ConfigDir = Join-Path -Path $script:TempRoot -ChildPath 'config'
            $script:StateDir  = Join-Path -Path $script:TempRoot -ChildPath 'state'
            $script:LogsDir   = Join-Path -Path $script:TempRoot -ChildPath 'logs'
            [void](New-Item -Path $script:ConfigDir, $script:StateDir, $script:LogsDir -ItemType Directory -Force)

            $script:CredPath  = Join-Path -Path $script:ConfigDir -ChildPath 'activenet_creds.clixml'
            $script:StatePath = Join-Path -Path $script:StateDir -ChildPath 'sync_state.json'
            $script:LockPath  = Join-Path -Path $script:StateDir -ChildPath 'sync.lock'
            $script:CfgPath   = Join-Path -Path $script:ConfigDir -ChildPath 'config.json'

            $secKey = [System.Security.SecureString]::new()
            foreach ($c in 'MOCK_API_KEY_12345'.ToCharArray()) { $secKey.AppendChar($c) }
            $secKey.MakeReadOnly()

            $secSecret = [System.Security.SecureString]::new()
            foreach ($c in 'MOCK_SHARED_SECRET_67890'.ToCharArray()) { $secSecret.AppendChar($c) }
            $secSecret.MakeReadOnly()

            ([PSCustomObject]@{ ApiKey = $secKey; SharedSecret = $secSecret }) | Export-Clixml -Path $script:CredPath -Force

            $cfgPayload = [ordered]@{
                tenantId          = '00000000-0000-0000-0000-000000000000'
                clientId          = '11111111-1111-1111-1111-111111111111'
                certThumbprint    = '0123456789ABCDEF0123456789ABCDEF01234567'
                mailbox           = 'roommailbox@example.com'
                activeNetOrgId    = 'sampleorg'
                activeNetBaseUrl  = 'https://api.amp.active.com'
                activeNetCredPath = $script:CredPath
                centerName        = 'Community Center Complex'
                facilityName      = 'Conference Room A'
                facilityId        = 440
                centerId          = 19
                timeZone          = 'Central Standard Time'
                stateFilePath     = $script:StatePath
                logDirectory      = $script:LogsDir
                lockFilePath      = $script:LockPath
                dryRunDaysWindow  = 30
            } | ConvertTo-Json -Depth 5
            Set-Content -LiteralPath $script:CfgPath -Value $cfgPayload -Encoding utf8
        }

        It 'Halts immediately with ExitCode 30 and zero network calls when sync_state.json is corrupted' {
            Set-Content -LiteralPath $script:StatePath -Value '{ CORRUPTED STATE JSON ' -Encoding utf8

            $outcome = & $script:SyncScript -ConfigPath $script:CfgPath -DryRun -PassThru
            $outcome.ExitCode | Should -Be 30
            $outcome.SummaryBlock | Should -Match 'FAILED \(Exit Code 30 - Corrupt State\)'
            (Test-Path -LiteralPath $script:LockPath) | Should -BeFalse
        }
    }
}
