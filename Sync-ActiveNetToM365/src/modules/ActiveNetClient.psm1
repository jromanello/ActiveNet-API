#Requires -Version 7.0
Set-StrictMode -Version Latest

function ConvertFrom-SecureToPlainInternal {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureValue
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function New-ActiveNetSignature {
    <#
    .SYNOPSIS
        Computes the ACTIVENet enhanced-security SHA-256 dynamic digital signature.
    .DESCRIPTION
        Generates the 64-character lowercase hexadecimal SHA-256 hash of (api_key + shared_secret + epoch_seconds).
        Accepts SecureString credentials so secrets are never exposed in plaintext parameters.
    .PARAMETER ApiKey
        The ACTIVENet API Key as a SecureString.
    .PARAMETER SharedSecret
        The ACTIVENet Shared Secret as a SecureString.
    .PARAMETER EpochSeconds
        Unix timestamp in seconds. Defaults to current UTC epoch seconds.
    .OUTPUTS
        System.String. 64-character lowercase hex signature.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory SHA-256 signature calculation')]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$ApiKey,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SharedSecret,

        [Parameter(Mandatory = $false)]
        [int64]$EpochSeconds = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    )

    $plainKey = ConvertFrom-SecureToPlainInternal -SecureValue $ApiKey
    $plainSecret = ConvertFrom-SecureToPlainInternal -SecureValue $SharedSecret

    $payload = "$plainKey$plainSecret$EpochSeconds"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-DateChunkWindow {
    <#
    .SYNOPSIS
        Splits a date range into contiguous chunks of at most ChunkDays days.
    .DESCRIPTION
        Divides [StartDate, EndDate] into sequential windows no larger than ChunkDays (default 90 days)
        for safe querying against ACTIVENet GetFacilitySchedules.
    .PARAMETER StartDate
        Start of the overall query range.
    .PARAMETER EndDate
        End of the overall query range. Must be greater than StartDate.
    .PARAMETER ChunkDays
        Maximum days per chunk. Defaults to 90.
    .OUTPUTS
        PSCustomObject[] with ChunkStart and ChunkEnd properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$ChunkDays = 90
    )

    if ($EndDate -le $StartDate) {
        throw "EndDate ($($EndDate.ToString('o'))) must be greater than StartDate ($($StartDate.ToString('o')))."
    }

    $chunks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cursor = $StartDate

    while ($cursor -lt $EndDate) {
        $nextEnd = $cursor.AddDays($ChunkDays)
        if ($nextEnd -gt $EndDate) {
            $nextEnd = $EndDate
        }

        $chunks.Add([PSCustomObject]@{
            ChunkStart = $cursor
            ChunkEnd   = $nextEnd
        })

        $cursor = $nextEnd
    }

    return $chunks.ToArray()
}

function Invoke-ActiveNetPagedGet {
    <#
    .SYNOPSIS
        Executes a paged HTTP GET against an ACTIVENet System API endpoint with retry and integrity tracking.
    .DESCRIPTION
        Queries the specified ACTIVENet resource across all pages using the page_info header.
        Validates headers.response_code ("0000" = success, "0001" = empty, any other code = failure).
        Applies exponential backoff strictly for transient network failures and HTTP 5xx errors.
        Returns the collected records alongside a circuit-breaker integrity record.
    .PARAMETER BaseUrl
        The ACTIVENet host base URL (e.g., https://api.amp.active.com).
    .PARAMETER OrgId
        The ACTIVENet organization identifier (e.g., your-org-id).
    .PARAMETER ResourcePath
        The API resource path (e.g., facilityschedules or facilities).
    .PARAMETER QueryParameters
        Hashtable of query string parameters (excluding api_key and sig).
    .PARAMETER SecretPackage
        PSCustomObject containing SecureString ApiKey and SharedSecret.
    .PARAMETER PageSize
        Records per page (1 to 500). Defaults to 250.
    .PARAMETER MaxRetries
        Maximum retries for transient network or HTTP 5xx errors. Defaults to 3.
    .PARAMETER BaseBackoffMs
        Base backoff delay in milliseconds for exponential retry. Defaults to 1000.
    .PARAMETER PacingDelayMs
        Inter-request delay in milliseconds to respect gateway QPS limits. Defaults to 1500.
    .OUTPUTS
        PSCustomObject containing Records and Integrity (pagesExpected, pagesFetched, codesSeen, httpStatuses, isComplete, errorMessage).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrgId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourcePath,

        [Parameter(Mandatory = $false)]
        [hashtable]$QueryParameters = @{},

        [Parameter(Mandatory = $true)]
        [Alias('Credential')]
        [PSCustomObject]$SecretPackage,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 500)]
        [int]$PageSize = 250,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 60000)]
        [int]$BaseBackoffMs = 1000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10000)]
        [int]$PacingDelayMs = 1500
    )

    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    $codesSeen = [System.Collections.Generic.List[string]]::new()
    $httpStatuses = [System.Collections.Generic.List[int]]::new()

    $pagesExpected = 1
    $pagesFetched = 0
    $isComplete = $true
    $errorMessage = $null

    $trimmedBase = $BaseUrl.TrimEnd('/')
    $trimmedResource = $ResourcePath.TrimStart('/')
    $serviceName = 'anet-systemapi-sec'

    $plainKey = ConvertFrom-SecureToPlainInternal -SecureValue $SecretPackage.ApiKey

    $queryPairs = [System.Collections.Generic.List[string]]::new()
    foreach ($key in ($QueryParameters.Keys | Sort-Object)) {
        $val = [string]$QueryParameters[$key]
        $encodedVal = [System.Uri]::EscapeDataString($val)
        $queryPairs.Add("$key=$encodedVal")
    }
    $queryPrefix = if ($queryPairs.Count -gt 0) { ($queryPairs -join '&') + '&' } else { '' }

    $pageNumber = 1
    $hasMorePages = $true

    while ($hasMorePages) {
        if ($PacingDelayMs -gt 0 -and $pageNumber -gt 1) {
            Start-Sleep -Milliseconds $PacingDelayMs
        }

        $pageInfoJson = ([ordered]@{
            page_number            = $pageNumber
            total_records_per_page = $PageSize
        } | ConvertTo-Json -Compress)

        $headers = @{
            'Accept'    = 'application/json'
            'page_info' = $pageInfoJson
        }

        $attempt = 0
        $pageResponse = $null
        $requestSucceeded = $false

        while ($attempt -le $MaxRetries) {
            $attempt++
            $epochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $sig = New-ActiveNetSignature -ApiKey $SecretPackage.ApiKey -SharedSecret $SecretPackage.SharedSecret -EpochSeconds $epochSeconds
            $uri = "$trimmedBase/$serviceName/$OrgId/api/v1/$trimmedResource`?$queryPrefix" + "api_key=$plainKey&sig=$sig"

            try {
                $pageResponse = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
                $httpStatuses.Add(200)
                $requestSucceeded = $true
                break
            } catch {
                $statusCode = 0
                if ($null -ne $_.Exception -and $null -ne $_.Exception.PSObject.Properties['Response'] -and $null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                if ($statusCode -gt 0) {
                    $httpStatuses.Add($statusCode)
                } else {
                    # 0 indicates network-level exception (DNS, socket timeout, connection reset)
                    $httpStatuses.Add(0)
                }

                $errText = $_.ToString()
                if ($null -ne $_.Exception -and $null -ne $_.Exception.Message) { $errText += " " + $_.Exception.Message }
                $isQps = ($statusCode -eq 429) -or ($statusCode -eq 403 -and $errText -match '(?i)over\s*qps')
                $isRetryable = ($statusCode -eq 0) -or ($statusCode -ge 500 -and $statusCode -lt 600) -or $isQps
                if ($isRetryable -and $attempt -le $MaxRetries) {
                    $delayMs = [int]($BaseBackoffMs * [Math]::Pow(2, ($attempt - 1)))
                    if ($delayMs -gt 0) {
                        Start-Sleep -Milliseconds $delayMs
                    }
                    continue
                }

                $isComplete = $false
                $errorMessage = "HTTP/Network failure on page $pageNumber (Status: $statusCode): $($_.Exception.Message)"
                break
            }
        }

        if (-not $requestSucceeded) {
            break
        }

        if ($null -eq $pageResponse -or
            $null -eq $pageResponse.PSObject.Properties['headers'] -or
            $null -eq $pageResponse.headers -or
            $null -eq $pageResponse.headers.PSObject.Properties['response_code']) {
            $isComplete = $false
            $errorMessage = "Malformed ACTIVENet response on page $pageNumber`: missing headers.response_code."
            break
        }

        $respCode = [string]$pageResponse.headers.response_code
        $codesSeen.Add($respCode)

        if ($respCode -eq '0001') {
            # Documented empty result set code
            $pagesFetched++
            if ($pageNumber -eq 1) {
                $pagesExpected = 1
            } else {
                $pagesExpected = $pagesFetched
            }
            $hasMorePages = $false
            break
        }

        if ($respCode -ne '0000') {
            $respMsg = if ($null -ne $pageResponse.headers.PSObject.Properties['response_message']) {
                [string]$pageResponse.headers.response_message
            } else {
                'Unknown API error'
            }
            $isComplete = $false
            $errorMessage = "ACTIVENet error response_code '$respCode' on page $pageNumber`: $respMsg"
            break
        }

        $pagesFetched++

        if ($null -eq $pageResponse.PSObject.Properties['body'] -or $null -eq $pageResponse.body) {
            $isComplete = $false
            $errorMessage = "Malformed ACTIVENet response on page $pageNumber`: missing body array."
            break
        }

        $bodyArray = @($pageResponse.body)
        foreach ($item in $bodyArray) {
            if ($null -ne $item) {
                $records.Add($item)
            }
        }

        $explicitTotalPages = $null
        if ($null -ne $pageResponse.headers.PSObject.Properties['page_info'] -and
            $null -ne $pageResponse.headers.page_info -and
            $null -ne $pageResponse.headers.page_info.PSObject.Properties['total_page']) {
            $explicitTotalPages = [int]$pageResponse.headers.page_info.total_page
        }

        if ($null -ne $explicitTotalPages -and $explicitTotalPages -gt 0) {
            $pagesExpected = $explicitTotalPages
            if ($pageNumber -ge $explicitTotalPages) {
                $hasMorePages = $false
            } else {
                $pageNumber++
            }
        } else {
            if ($bodyArray.Count -lt $PageSize) {
                $pagesExpected = $pagesFetched
                $hasMorePages = $false
            } else {
                $pagesExpected = $pagesFetched + 1
                $pageNumber++
            }
        }
    }

    if ($pagesFetched -ne $pagesExpected) {
        $isComplete = $false
    }

    return [PSCustomObject]@{
        Records   = $records.ToArray()
        Integrity = [PSCustomObject]@{
            pagesExpected = $pagesExpected
            pagesFetched  = $pagesFetched
            codesSeen     = $codesSeen.ToArray()
            httpStatuses  = $httpStatuses.ToArray()
            isComplete    = $isComplete
            errorMessage  = $errorMessage
        }
    }
}

function Get-ActiveNetFacilitySchedule {
    <#
    .SYNOPSIS
        Retrieves all facility reservation schedules across a future window using 90-day chunking.
    .DESCRIPTION
        Queries ACTIVENet GetFacilitySchedules (/facilityschedules) in rolling 90-day date chunks,
        handling pagination and aggregating circuit-breaker integrity telemetry across all chunks.
    .PARAMETER BaseUrl
        The ACTIVENet host base URL.
    .PARAMETER OrgId
        The ACTIVENet organization ID.
    .PARAMETER FacilityId
        The numeric facility_id (e.g., 440 for NCC - Conference Room).
    .PARAMETER StartDate
        Start date/time of the query window.
    .PARAMETER EndDate
        End date/time of the query window.
    .PARAMETER SecretPackage
        PSCustomObject with SecureString ApiKey and SharedSecret.
    .PARAMETER ChunkDays
        Maximum days per chunk request. Defaults to 90.
    .PARAMETER PageSize
        Records per page (up to 500). Defaults to 250.
    .PARAMETER MaxRetries
        Maximum retries for transient 5xx/network errors. Defaults to 3.
    .PARAMETER BaseBackoffMs
        Base backoff in milliseconds. Defaults to 1000.
    .PARAMETER PacingDelayMs
        Inter-request QPS pacing delay in milliseconds. Defaults to 1500.
    .OUTPUTS
        PSCustomObject containing Records and aggregated Integrity telemetry.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrgId,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$FacilityId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [Alias('Credential')]
        [PSCustomObject]$SecretPackage,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$ChunkDays = 90,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 500)]
        [int]$PageSize = 250,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 60000)]
        [int]$BaseBackoffMs = 1000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10000)]
        [int]$PacingDelayMs = 1500
    )

    $chunks = Get-DateChunkWindow -StartDate $StartDate -EndDate $EndDate -ChunkDays $ChunkDays

    $allRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allCodesSeen = [System.Collections.Generic.List[string]]::new()
    $allHttpStatuses = [System.Collections.Generic.List[int]]::new()
    $totalPagesExpected = 0
    $totalPagesFetched = 0
    $overallComplete = $true
    $errorMessages = [System.Collections.Generic.List[string]]::new()

    $chunkIndex = 0
    foreach ($chunk in $chunks) {
        $chunkIndex++
        if ($PacingDelayMs -gt 0 -and $chunkIndex -gt 1) {
            Start-Sleep -Milliseconds $PacingDelayMs
        }

        $queryParams = @{
            facility_ids = [string]$FacilityId
            date_from    = $chunk.ChunkStart.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
            date_to      = $chunk.ChunkEnd.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        }

        $chunkResult = Invoke-ActiveNetPagedGet `
            -BaseUrl $BaseUrl `
            -OrgId $OrgId `
            -ResourcePath 'facilityschedules' `
            -QueryParameters $queryParams `
            -SecretPackage $SecretPackage `
            -PageSize $PageSize `
            -MaxRetries $MaxRetries `
            -BaseBackoffMs $BaseBackoffMs `
            -PacingDelayMs $PacingDelayMs

        $totalPagesExpected += $chunkResult.Integrity.pagesExpected
        $totalPagesFetched += $chunkResult.Integrity.pagesFetched

        foreach ($code in $chunkResult.Integrity.codesSeen) {
            $allCodesSeen.Add($code)
        }
        foreach ($status in $chunkResult.Integrity.httpStatuses) {
            $allHttpStatuses.Add($status)
        }

        if (-not $chunkResult.Integrity.isComplete) {
            $overallComplete = $false
            if (-not [string]::IsNullOrWhiteSpace($chunkResult.Integrity.errorMessage)) {
                $errorMessages.Add($chunkResult.Integrity.errorMessage)
            }
            break
        }

        foreach ($rec in $chunkResult.Records) {
            $allRecords.Add($rec)
        }
    }

    return [PSCustomObject]@{
        Records   = $allRecords.ToArray()
        Integrity = [PSCustomObject]@{
            pagesExpected = $totalPagesExpected
            pagesFetched  = $totalPagesFetched
            codesSeen     = $allCodesSeen.ToArray()
            httpStatuses  = $allHttpStatuses.ToArray()
            chunksTotal   = $chunks.Count
            chunksFetched = $chunkIndex
            isComplete    = $overallComplete
            errorMessage  = if ($errorMessages.Count -gt 0) { $errorMessages -join '; ' } else { $null }
        }
    }
}

function Get-ActiveNetActivityDetailMap {
    <#
    .SYNOPSIS
        Retrieves activity detail metadata (event_notes, user_notes, supervisor) for a set of activity_numbers.
    .DESCRIPTION
        Deduplicates non-empty activity_number values, queries GET /activities?activity_number={num} to resolve
        the internal integer activity_id, and queries GET /activities/{activity_id} (GetActivityDetail) to extract
        pattern event_notes (filtered to TargetFacilityId when possible), user_notes, and supervisor.
    .PARAMETER BaseUrl
        The ACTIVENet host base URL.
    .PARAMETER OrgId
        The ACTIVENet organization ID.
    .PARAMETER ActivityNumbers
        Array of activity_number strings to resolve.
    .PARAMETER SecretPackage
        PSCustomObject with SecureString ApiKey and SharedSecret.
    .PARAMETER TargetFacilityId
        Optional facility_id used to prioritize pattern event_notes matching the target room.
    .PARAMETER PacingDelayMs
        Inter-request QPS pacing delay in milliseconds. Defaults to 650.
    .OUTPUTS
        Hashtable keyed by activity_number containing EventNotes, UserNotes, Supervisor, and ActivityId.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrgId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]]$ActivityNumbers = @(),

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$SecretPackage,

        [Parameter(Mandatory = $false)]
        [int]$TargetFacilityId = 0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10000)]
        [int]$PacingDelayMs = 650
    )

    $detailMap = @{}
    $uniqueNums = @(
        $ActivityNumbers |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Select-Object -Unique
    )

    foreach ($actNum in $uniqueNums) {
        if ($PacingDelayMs -gt 0) {
            Start-Sleep -Milliseconds $PacingDelayMs
        }

        $searchRes = Invoke-ActiveNetPagedGet `
            -BaseUrl $BaseUrl `
            -OrgId $OrgId `
            -ResourcePath 'activities' `
            -QueryParameters @{ activity_number = $actNum } `
            -SecretPackage $SecretPackage `
            -PageSize 50 `
            -PacingDelayMs $PacingDelayMs

        if ($null -eq $searchRes -or @($searchRes.Records).Count -eq 0) {
            continue
        }

        $actSummary = @($searchRes.Records)[0]
        if ($null -eq $actSummary -or $null -eq $actSummary.PSObject.Properties['activity_id'] -or $null -eq $actSummary.activity_id) {
            continue
        }

        $actId = [int]$actSummary.activity_id
        if ($PacingDelayMs -gt 0) {
            Start-Sleep -Milliseconds $PacingDelayMs
        }

        $detailRes = Invoke-ActiveNetPagedGet `
            -BaseUrl $BaseUrl `
            -OrgId $OrgId `
            -ResourcePath "activities/$actId" `
            -SecretPackage $SecretPackage `
            -PageSize 50 `
            -PacingDelayMs $PacingDelayMs

        if ($null -eq $detailRes -or @($detailRes.Records).Count -eq 0) {
            continue
        }

        $detailObj = @($detailRes.Records)[0]
        $supervisor = if ($null -ne $detailObj.PSObject.Properties['supervisor'] -and -not [string]::IsNullOrWhiteSpace([string]$detailObj.supervisor)) {
            ([string]$detailObj.supervisor).Trim()
        } else {
            ''
        }
        $userNotes = if ($null -ne $detailObj.PSObject.Properties['user_notes'] -and -not [string]::IsNullOrWhiteSpace([string]$detailObj.user_notes)) {
            ([string]$detailObj.user_notes).Trim()
        } else {
            ''
        }

        $patternNotesList = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $detailObj.PSObject.Properties['activity_patterns'] -and $null -ne $detailObj.activity_patterns) {
            foreach ($pat in @($detailObj.activity_patterns)) {
                if ($null -eq $pat) { continue }
                $matchesFacility = $true
                if ($TargetFacilityId -gt 0 -and
                    $null -ne $pat.PSObject.Properties['pattern_facilities'] -and
                    $null -ne $pat.pattern_facilities -and
                    @($pat.pattern_facilities).Count -gt 0) {
                    $facMatch = @($pat.pattern_facilities | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['facility_id'] -and [int]$_.facility_id -eq $TargetFacilityId })
                    $matchesFacility = ($facMatch.Count -gt 0)
                }

                if ($matchesFacility -and
                    $null -ne $pat.PSObject.Properties['event_notes'] -and
                    -not [string]::IsNullOrWhiteSpace([string]$pat.event_notes)) {
                    $noteText = ([string]$pat.event_notes).Trim()
                    if (-not $patternNotesList.Contains($noteText)) {
                        $patternNotesList.Add($noteText)
                    }
                }
            }

            # Fallback if no facility-specific pattern matched
            if ($patternNotesList.Count -eq 0) {
                foreach ($pat in @($detailObj.activity_patterns)) {
                    if ($null -ne $pat -and
                        $null -ne $pat.PSObject.Properties['event_notes'] -and
                        -not [string]::IsNullOrWhiteSpace([string]$pat.event_notes)) {
                        $noteText = ([string]$pat.event_notes).Trim()
                        if (-not $patternNotesList.Contains($noteText)) {
                            $patternNotesList.Add($noteText)
                        }
                    }
                }
            }
        }

        $combinedNotes = ($patternNotesList -join "`n").Trim()
        if ([string]::IsNullOrWhiteSpace($combinedNotes) -and -not [string]::IsNullOrWhiteSpace($userNotes)) {
            $combinedNotes = $userNotes
        }

        $detailMap[$actNum] = [PSCustomObject]@{
            ActivityNumber = $actNum
            ActivityId     = $actId
            Supervisor     = $supervisor
            EventNotes     = $combinedNotes
            UserNotes      = $userNotes
        }
    }

    return $detailMap
}

Export-ModuleMember -Function @(
    'New-ActiveNetSignature',
    'Get-DateChunkWindow',
    'Invoke-ActiveNetPagedGet',
    'Get-ActiveNetFacilitySchedule',
    'Get-ActiveNetActivityDetailMap'
)
