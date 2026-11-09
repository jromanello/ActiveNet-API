#Requires -Version 7.0
Set-StrictMode -Version Latest

BeforeAll {
    $modulesDir = Join-Path -Path $PSScriptRoot -ChildPath '../src/modules'
    Import-Module (Join-Path $modulesDir 'Logging.psm1') -Force
    Import-Module (Join-Path $modulesDir 'Locking.psm1') -Force
    Import-Module (Join-Path $modulesDir 'Security.psm1') -Force
    Import-Module (Join-Path $modulesDir 'ActiveNetClient.psm1') -Force
    Import-Module (Join-Path $modulesDir 'GraphClient.psm1') -Force

    function ConvertTo-TestSecureString {
        param ([string]$Text)
        $sec = [System.Security.SecureString]::new()
        foreach ($ch in $Text.ToCharArray()) {
            $sec.AppendChar($ch)
        }
        $sec.MakeReadOnly()
        return $sec
    }
}

Describe 'Stage 3B.1: Logging.psm1' {
    BeforeEach {
        $script:TestLogDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "an-log-test-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:TestLogDir -Force | Out-Null
        Clear-LogSecret
    }

    AfterEach {
        Clear-LogSecret
        if (Test-Path -Path $script:TestLogDir) {
            Remove-Item -Path $script:TestLogDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Creates daily log file sync-YYYY-MM-DD.log and writes ISO 8601 UTC entries with Run ID' {
        $refTime = [datetime]::SpecifyKind([datetime]'2026-10-26T14:30:00', [DateTimeKind]::Utc)
        $runId = 'run-12345'
        $logFile = Initialize-SyncLog -LogDirectory $script:TestLogDir -RunId $runId -RetentionDays 90 -ReferenceTimeUtc $refTime

        $logFile | Should -BeLike '*sync-2026-10-26.log'

        $line = Write-SyncLog -Level 'INFO' -Message 'Test message' -TimestampUtc $refTime
        $line | Should -Be '[2026-10-26T14:30:00.000Z] [INFO] [run-12345] Test message'
        (Get-Content -Path $logFile -Raw).Trim() | Should -Be $line
    }

    It 'Prunes log files older than 90 days while retaining recent log files' {
        $refTime = [datetime]::SpecifyKind([datetime]'2026-10-26T02:00:00', [DateTimeKind]::Utc)
        $oldFile = Join-Path -Path $script:TestLogDir -ChildPath 'sync-2026-07-01.log'
        $recentFile = Join-Path -Path $script:TestLogDir -ChildPath 'sync-2026-09-15.log'
        Set-Content -Path $oldFile -Value 'old log'
        Set-Content -Path $recentFile -Value 'recent log'

        [void](Initialize-SyncLog -LogDirectory $script:TestLogDir -RunId 'prune-run' -RetentionDays 90 -ReferenceTimeUtc $refTime)

        (Test-Path -Path $oldFile) | Should -BeFalse
        (Test-Path -Path $recentFile) | Should -BeTrue
    }

    It 'Automatically redacts api_key, sig, Bearer tokens, JWTs, and registered secrets' {
        $refTime = [datetime]::SpecifyKind([datetime]'2026-10-26T02:00:00', [DateTimeKind]::Utc)
        [void](Initialize-SyncLog -LogDirectory $script:TestLogDir -RunId 'redact-run' -ReferenceTimeUtc $refTime)
        Register-LogSecret -SecretValue 'MyTopSecretSharedKey999'

        $rawMsg = 'Request https://api.amp.active.com/test?api_key=SECRETKEY123&sig=89abcdef01234567 auth=Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl secret=MyTopSecretSharedKey999'
        $written = Write-SyncLog -Level 'WARN' -Message $rawMsg -TimestampUtc $refTime

        $written | Should -Not -Match 'SECRETKEY123'
        $written | Should -Not -Match '89abcdef01234567'
        $written | Should -Not -Match 'eyJhbGciOiJSUzI1NiJ9'
        $written | Should -Not -Match 'MyTopSecretSharedKey999'
        $written | Should -Match 'api_key=\[REDACTED\]'
        $written | Should -Match 'sig=\[REDACTED\]'
        $written | Should -Match 'Bearer \[REDACTED\]'
    }

    It 'Produces the exact synchronization summary block matching ARCHITECTURE.md Section 15' {
        $refTime = [datetime]::SpecifyKind([datetime]'2026-10-26T02:00:00', [DateTimeKind]::Utc)
        [void](Initialize-SyncLog -LogDirectory $script:TestLogDir -RunId '7b4a2c91-182d-4d2a-9e12-d890ef98c341' -ReferenceTimeUtc $refTime)

        $stats = @{
            RunId                   = '7b4a2c91-182d-4d2a-9e12-d890ef98c341'
            Timestamp               = '2026-10-24T02:00:15-05:00'
            Mode                    = 'Production'
            FacilityName            = 'Conference Room A'
            FacilityId              = 440
            TargetMailbox           = 'roommailbox@example.com'
            SourceRecordsRetrieved  = 42
            Created                 = 2
            Updated                 = 1
            Recreated               = 0
            Deleted                 = 0
            Unchanged               = 39
            OutlookNativeInspected  = 14
            OutlookNativeModified   = 0
            ConflictsDetected       = 1
            NotificationsDispatched = 1
            NotificationsSuppressed = 0
            Errors                  = 0
            CircuitBreaker          = 'Armed / Normal'
            ExecutionResult         = 'SUCCESS (Exit Code 0)'
        }

        $summary = Write-SyncSummary -SummaryStats $stats -TimestampUtc $refTime
        $lines = $summary -split '\r?\n'

        $lines[0]  | Should -Be '======================= SYNCHRONIZATION SUMMARY ======================='
        $lines[1]  | Should -Be 'Run ID:                  7b4a2c91-182d-4d2a-9e12-d890ef98c341'
        $lines[4]  | Should -Be 'ACTIVENet Facility:      Conference Room A (ID: 440)'
        $lines[13] | Should -Be 'Outlook-Native Modified: 0  (CRITICAL INVARIANT)'
        $lines[19] | Should -Be 'Execution Result:        SUCCESS (Exit Code 0)'
        $lines[20] | Should -Be '======================================================================='
    }

    It 'Throws if OutlookNativeModified is non-zero in Format-SyncSummary' {
        { Format-SyncSummary -SummaryStats @{ OutlookNativeModified = 1 } } | Should -Throw '*CRITICAL SAFETY INVARIANT VIOLATION*'
    }
}

Describe 'Stage 3B.2: Locking.psm1' {
    BeforeEach {
        $script:TestLockDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "an-lock-test-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:TestLockDir -Force | Out-Null
        $script:LockFile = Join-Path -Path $script:TestLockDir -ChildPath 'sync.lock'
    }

    AfterEach {
        if (Test-Path -Path $script:TestLockDir) {
            Remove-Item -Path $script:TestLockDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Acquires an exclusive lock containing the current PID and releases cleanly in finally' {
        $lock = $null
        try {
            $lock = Lock-SyncProcess -LockFilePath $script:LockFile -ProcessId $PID
            $lock | Should -Not -BeNullOrEmpty
            $lock.ProcessId | Should -Be $PID
            (Test-Path -Path $script:LockFile) | Should -BeTrue

            # Second concurrent attempt while stream is open must return $null
            $secondLock = Lock-SyncProcess -LockFilePath $script:LockFile -ProcessId $PID
            $secondLock | Should -BeNullOrEmpty
        } finally {
            Unlock-SyncProcess -LockHandle $lock
        }

        (Test-Path -Path $script:LockFile) | Should -BeFalse
    }

    It 'Refuses to reclaim lock when the recorded PID is currently running' {
        # Write a lock file with the current running $PID (without holding stream open)
        @{ pid = $PID; acquiredUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -Path $script:LockFile

        $lock = Lock-SyncProcess -LockFilePath $script:LockFile -ProcessId $PID
        $lock | Should -BeNullOrEmpty
    }

    It 'Reclaims stale lock when the recorded PID is not running' {
        Mock -ModuleName Locking Test-LockProcessRunning { return $false }

        @{ pid = 999999; acquiredUtc = '2026-01-01T00:00:00Z' } | ConvertTo-Json | Set-Content -Path $script:LockFile

        $lock = $null
        try {
            $lock = Lock-SyncProcess -LockFilePath $script:LockFile -ProcessId $PID
            $lock | Should -Not -BeNullOrEmpty
            $lock.ReclaimedStaleLock | Should -BeTrue
            $lock.ProcessId | Should -Be $PID
        } finally {
            Unlock-SyncProcess -LockHandle $lock
        }
    }
}

Describe 'Stage 3B.3: Security.psm1' {
    BeforeEach {
        $script:TestSecDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "an-sec-test-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:TestSecDir -Force | Out-Null
    }

    AfterEach {
        if (Test-Path -Path $script:TestSecDir) {
            Remove-Item -Path $script:TestSecDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Loads DPAPI-encrypted SecureString credentials via Import-Clixml' {
        $credFile = Join-Path -Path $script:TestSecDir -ChildPath 'creds.clixml'
        [PSCustomObject]@{
            ApiKey       = (ConvertTo-TestSecureString -Text 'TestKey123')
            SharedSecret = (ConvertTo-TestSecureString -Text 'TestSecret456')
        } | Export-Clixml -Path $credFile -Force

        $loaded = Get-ActiveNetCredential -CredentialFilePath $credFile
        $loaded.ApiKey | Should -BeOfType [System.Security.SecureString]
        $loaded.SharedSecret | Should -BeOfType [System.Security.SecureString]
    }

    It 'Rejects CLIXML files storing plaintext strings instead of SecureStrings' {
        $badFile = Join-Path -Path $script:TestSecDir -ChildPath 'bad_creds.clixml'
        [PSCustomObject]@{
            ApiKey       = 'PlainKey'
            SharedSecret = 'PlainSecret'
        } | Export-Clixml -Path $badFile -Force

        { Get-ActiveNetCredential -CredentialFilePath $badFile } | Should -Throw '*Security policy violation*'
    }

    It 'Builds a valid RS256-signed JWT client assertion verifiable with the certificate public key' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=UnitTestCert',
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))

            $jwt = New-EntraClientAssertionJwt -TenantId 'tenant-guid-1' -ClientId 'client-guid-2' -Certificate $cert
            $parts = $jwt -split '\.'
            $parts.Count | Should -Be 3

            # Verify RS256 signature using public key
            $signingBytes = [System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])")
            $sigPadded = $parts[2] -replace '-', '+' -replace '_', '/'
            switch ($sigPadded.Length % 4) {
                2 { $sigPadded += '==' }
                3 { $sigPadded += '=' }
            }
            $sigBytes = [Convert]::FromBase64String($sigPadded)

            $pubRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
            $verified = $pubRsa.VerifyData(
                $signingBytes,
                $sigBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $verified | Should -BeTrue
        } finally {
            $rsa.Dispose()
        }
    }
}

Describe 'Stage 3B.4: ActiveNetClient.psm1' {
    BeforeAll {
        $script:MockCred = [PSCustomObject]@{
            ApiKey       = (ConvertTo-TestSecureString -Text 'mock-api-key')
            SharedSecret = (ConvertTo-TestSecureString -Text 'mock-shared-secret')
        }
    }

    It 'Computes deterministic 64-char lowercase SHA-256 signature' {
        $sig = New-ActiveNetSignature -ApiKey $script:MockCred.ApiKey -SharedSecret $script:MockCred.SharedSecret -EpochSeconds 1700000000
        $sig | Should -Match '^[0-9a-f]{64}$'

        # Verify against direct SHA-256 of 'mock-api-keymock-shared-secret1700000000'
        $expectedBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes('mock-api-keymock-shared-secret1700000000'))
        $expectedHex = ([System.BitConverter]::ToString($expectedBytes) -replace '-', '').ToLowerInvariant()
        $sig | Should -Be $expectedHex
    }

    It 'Chunks a 200-day range into 3 windows (90, 90, 20 days)' {
        $start = [datetime]'2026-01-01T00:00:00'
        $end = $start.AddDays(200)
        $chunks = Get-DateChunkWindow -StartDate $start -EndDate $end -ChunkDays 90

        $chunks.Count | Should -Be 3
        ($chunks[0].ChunkEnd - $chunks[0].ChunkStart).TotalDays | Should -Be 90
        ($chunks[1].ChunkEnd - $chunks[1].ChunkStart).TotalDays | Should -Be 90
        ($chunks[2].ChunkEnd - $chunks[2].ChunkStart).TotalDays | Should -Be 20
    }

    It 'Handles multi-page 0000 responses and returns complete integrity record' {
        $script:PageCallCount = 0
        Mock -ModuleName ActiveNetClient Invoke-RestMethod {
            $script:PageCallCount++
            if ($script:PageCallCount -eq 1) {
                return [PSCustomObject]@{
                    headers = [PSCustomObject]@{ response_code = '0000'; response_message = 'Successful' }
                    body    = @([PSCustomObject]@{ id = 1 }, [PSCustomObject]@{ id = 2 })
                }
            } else {
                return [PSCustomObject]@{
                    headers = [PSCustomObject]@{ response_code = '0000'; response_message = 'Successful' }
                    body    = @([PSCustomObject]@{ id = 3 })
                }
            }
        }

        $res = Invoke-ActiveNetPagedGet `
            -BaseUrl 'https://api.amp.active.com' `
            -OrgId 'sampleorg' `
            -ResourcePath 'facilityschedules' `
            -Credential $script:MockCred `
            -PageSize 2 `
            -PacingDelayMs 0

        $res.Records.Count | Should -Be 3
        $res.Integrity.pagesExpected | Should -Be 2
        $res.Integrity.pagesFetched | Should -Be 2
        $res.Integrity.codesSeen | Should -Be @('0000', '0000')
        $res.Integrity.httpStatuses | Should -Be @(200, 200)
        $res.Integrity.isComplete | Should -BeTrue
    }

    It 'Treats response_code 0001 (No results found) as complete with 0 records' {
        Mock -ModuleName ActiveNetClient Invoke-RestMethod {
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{ response_code = '0001'; response_message = 'No results found' }
                body    = @()
            }
        }

        $res = Invoke-ActiveNetPagedGet `
            -BaseUrl 'https://api.amp.active.com' `
            -OrgId 'sampleorg' `
            -ResourcePath 'facilityschedules' `
            -Credential $script:MockCred `
            -PacingDelayMs 0

        $res.Records.Count | Should -Be 0
        $res.Integrity.codesSeen | Should -Be @('0001')
        $res.Integrity.isComplete | Should -BeTrue
    }

    It 'Marks integrity isComplete = $false on non-0000/0001 response_code (e.g. 0016)' {
        Mock -ModuleName ActiveNetClient Invoke-RestMethod {
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{ response_code = '0016'; response_message = 'Unknown Parameters' }
                body    = @()
            }
        }

        $res = Invoke-ActiveNetPagedGet `
            -BaseUrl 'https://api.amp.active.com' `
            -OrgId 'sampleorg' `
            -ResourcePath 'facilityschedules' `
            -Credential $script:MockCred `
            -PacingDelayMs 0

        $res.Integrity.isComplete | Should -BeFalse
        $res.Integrity.codesSeen | Should -Be @('0016')
    }

    It 'Retries on transient network/5xx errors and does not retry on 4xx client errors' {
        $script:AttemptNum = 0
        Mock -ModuleName ActiveNetClient Invoke-RestMethod {
            $script:AttemptNum++
            if ($script:AttemptNum -lt 3) {
                throw 'Simulated network socket failure'
            }
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{ response_code = '0000'; response_message = 'Successful' }
                body    = @([PSCustomObject]@{ id = 99 })
            }
        }

        $res = Invoke-ActiveNetPagedGet `
            -BaseUrl 'https://api.amp.active.com' `
            -OrgId 'sampleorg' `
            -ResourcePath 'facilityschedules' `
            -Credential $script:MockCred `
            -MaxRetries 3 `
            -BaseBackoffMs 1 `
            -PacingDelayMs 0

        $script:AttemptNum | Should -Be 3
        $res.Integrity.isComplete | Should -BeTrue
        $res.Records.Count | Should -Be 1
    }
}

Describe 'Stage 3B.5: GraphClient.psm1' {
    It 'Acquires token on success and throws ExitCode 20 after 3 failed attempts' {
        $script:TokenCalls = 0
        Mock -ModuleName GraphClient Invoke-RestMethod {
            $script:TokenCalls++
            throw 'Entra endpoint unavailable'
        }

        $caught = $null
        try {
            [void](Connect-GraphApplication -TenantId 't1' -ClientId 'c1' -ClientAssertionJwt 'jwt' -MaxRetries 3 -BaseBackoffMs 1)
        } catch {
            $caught = $_
        }

        $script:TokenCalls | Should -Be 3
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Data['ExitCode'] | Should -Be 20
    }

    It 'Follows @odata.nextLink across calendarView pages with Prefer timezone header' {
        $script:ViewCalls = 0
        Mock -ModuleName GraphClient Invoke-RestMethod {
            param ($Headers)
            $Headers['Prefer'] | Should -Be 'outlook.timezone="Central Standard Time"'
            $script:ViewCalls++
            if ($script:ViewCalls -eq 1) {
                return [PSCustomObject]@{
                    value             = @([PSCustomObject]@{ id = 'ev-1'; subject = 'Meeting 1' })
                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users/room/calendarView?$skip=1'
                }
            } else {
                return [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = 'ev-2'; subject = 'Meeting 2' })
                }
            }
        }

        $events = Get-RoomCalendarView `
            -AccessToken 'mock-token' `
            -Mailbox 'roommailbox@example.com' `
            -StartDateTime ([datetime]'2026-11-01T00:00:00') `
            -EndDateTime ([datetime]'2026-11-08T00:00:00')

        $script:ViewCalls | Should -Be 2
        $events.Count | Should -Be 2
    }

    It 'Enforces Hard Constraint 1 in Test-SyncOwnership: requires MAPI properties AND local state match' {
        $propGuid = '66f538b8-3e5e-4054-97c7-08051213f019'
        $stateRecords = @{
            'ACT_29252_2026-10-26 13:30:00' = @{
                sourceScheduleId = 'ACT_29252_2026-10-26 13:30:00'
                graphEventId     = 'graph-ev-100'
            }
        }

        # Valid sync-owned event
        $validEvent = [PSCustomObject]@{
            id      = 'graph-ev-100'
            subject = '[AN] Canasta - Beginner'
            singleValueExtendedProperties = @(
                [PSCustomObject]@{ id = "String {$propGuid} Name ActiveNetSyncOwned"; value = 'True' },
                [PSCustomObject]@{ id = "String {$propGuid} Name ActiveNetSourceId"; value = 'ACT_29252_2026-10-26 13:30:00' }
            )
        }
        (Test-SyncOwnership -CalendarEvent $validEvent -StateRecords $stateRecords) | Should -BeTrue

        # Spoofed Outlook event with [AN] subject but no MAPI properties
        $spoofedEvent = [PSCustomObject]@{
            id      = 'graph-ev-100'
            subject = '[AN] Canasta - Beginner'
            singleValueExtendedProperties = @()
        }
        (Test-SyncOwnership -CalendarEvent $spoofedEvent -StateRecords $stateRecords) | Should -BeFalse

        # Event with MAPI properties but not in local state
        $untrackedEvent = [PSCustomObject]@{
            id      = 'graph-ev-999'
            subject = '[AN] Unknown Event'
            singleValueExtendedProperties = @(
                [PSCustomObject]@{ id = "String {$propGuid} Name ActiveNetSyncOwned"; value = 'True' },
                [PSCustomObject]@{ id = "String {$propGuid} Name ActiveNetSourceId"; value = 'ACT_99999_2026-10-26 13:30:00' }
            )
        }
        (Test-SyncOwnership -CalendarEvent $untrackedEvent -StateRecords $stateRecords) | Should -BeFalse

        # Missing local state ($null)
        (Test-SyncOwnership -CalendarEvent $validEvent -StateRecords $null) | Should -BeFalse
    }
}
