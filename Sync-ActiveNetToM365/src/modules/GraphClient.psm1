#Requires -Version 7.0
Set-StrictMode -Version Latest

$script:MapiPropertyGuid = '66f538b8-3e5e-4054-97c7-08051213f019'
$script:PropIdSyncOwned  = "String {$script:MapiPropertyGuid} Name ActiveNetSyncOwned"
$script:PropIdSourceId   = "String {$script:MapiPropertyGuid} Name ActiveNetSourceId"

function ConvertFrom-TokenToPlainInternal {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken
    )

    if ($AccessToken -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    return [string]$AccessToken
}

function Connect-GraphApplication {
    <#
    .SYNOPSIS
        Acquires an OAuth2 access token from Microsoft Entra ID using a signed JWT client assertion.
    .DESCRIPTION
        Requests an app-only token from the Microsoft identity platform v2.0 token endpoint.
        Retries up to MaxRetries (default 3) with exponential backoff. If all attempts fail,
        throws an exception tagged with ExitCode = 20 per ARCHITECTURE.md Section 13.
    .PARAMETER TenantId
        The Entra ID directory (tenant) ID.
    .PARAMETER ClientId
        The Entra ID application (client) ID.
    .PARAMETER ClientAssertionJwt
        The signed RFC 7523 JWT assertion string.
    .PARAMETER MaxRetries
        Maximum retry attempts after initial failure. Defaults to 3.
    .PARAMETER BaseBackoffMs
        Base backoff delay in milliseconds. Defaults to 1000.
    .OUTPUTS
        System.Security.SecureString representing the acquired Bearer access token.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientAssertionJwt,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 60000)]
        [int]$BaseBackoffMs = 1000
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id             = $ClientId
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $ClientAssertionJwt
        grant_type            = 'client_credentials'
        scope                 = 'https://graph.microsoft.com/.default'
    }

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ErrorAction Stop
            if ($null -eq $response -or
                $null -eq $response.PSObject.Properties['access_token'] -or
                [string]::IsNullOrWhiteSpace([string]$response.access_token)) {
                throw "Token response did not contain a valid access_token."
            }

            $secToken = [System.Security.SecureString]::new()
            foreach ($ch in ([string]$response.access_token).ToCharArray()) {
                $secToken.AppendChar($ch)
            }
            $secToken.MakeReadOnly()
            return $secToken
        } catch {
            $lastError = $_
            if ($attempt -lt $MaxRetries) {
                $delayMs = [int]($BaseBackoffMs * [Math]::Pow(2, ($attempt - 1)))
                if ($delayMs -gt 0) {
                    Start-Sleep -Milliseconds $delayMs
                }
            }
        }
    }

    $errMsg = "ExitCode=20: Failed to acquire Microsoft Graph token after $MaxRetries attempts. Last error: $($lastError.Exception.Message)"
    $ex = [System.InvalidOperationException]::new($errMsg, $lastError.Exception)
    $ex.Data['ExitCode'] = 20
    throw $ex
}

function Get-GraphEventExtendedProperty {
    <#
    .SYNOPSIS
        Extracts the ActiveNetSyncOwned and ActiveNetSourceId MAPI extended properties from a Graph event.
    .DESCRIPTION
        Inspects singleValueExtendedProperties on a Graph event object for property set
        {66f538b8-3e5e-4054-97c7-08051213f019} and returns their values.
    .PARAMETER CalendarEvent
        The Graph event PSCustomObject to inspect.
    .OUTPUTS
        PSCustomObject with SyncOwned and SourceId string properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$CalendarEvent
    )

    $syncOwnedVal = $null
    $sourceIdVal  = $null

    if ($null -ne $CalendarEvent -and
        $null -ne $CalendarEvent.PSObject.Properties['singleValueExtendedProperties'] -and
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

    return [PSCustomObject]@{
        SyncOwned = $syncOwnedVal
        SourceId  = $sourceIdVal
    }
}

function Test-SyncOwnership {
    <#
    .SYNOPSIS
        Positively verifies whether a Microsoft 365 calendar event is owned by this synchronization application.
    .DESCRIPTION
        Enforces Hard Constraint 1: An event is sync-owned if and only if:
        1. It carries singleValueExtendedProperty ActiveNetSyncOwned == "True" in property set
           {66f538b8-3e5e-4054-97c7-08051213f019}, AND
        2. It carries singleValueExtendedProperty ActiveNetSourceId with a non-empty value, AND
        3. Its ActiveNetSourceId matches a record in the provided local StateRecords dictionary/hashtable
           (and if ExpectedSourceId is passed, matches ExpectedSourceId; and if the state record specifies
           graphEventId, matches CalendarEvent.id).
        Subject text (including "[AN]"), timestamps, or similarity are never used as proof of ownership.
    .PARAMETER CalendarEvent
        The Microsoft Graph calendar event object to evaluate.
    .PARAMETER StateRecords
        Hashtable or PSCustomObject of local state records keyed by sourceScheduleId.
    .PARAMETER ExpectedSourceId
        Optional specific sourceScheduleId that the event must match.
    .OUTPUTS
        System.Boolean. $true if ownership is positively proven; $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$CalendarEvent,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$StateRecords,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedSourceId = ''
    )

    if ($null -eq $CalendarEvent -or $null -eq $StateRecords) {
        return $false
    }

    $extProps = Get-GraphEventExtendedProperty -CalendarEvent $CalendarEvent

    if ($extProps.SyncOwned -cne 'True') {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($extProps.SourceId)) {
        return $false
    }

    $sourceId = $extProps.SourceId

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceId) -and
        -not $sourceId.Equals($ExpectedSourceId, [System.StringComparison]::Ordinal)) {
        return $false
    }

    $matchedRecord = $null
    if ($StateRecords -is [System.Collections.IDictionary]) {
        if ($StateRecords.Contains($sourceId)) {
            $matchedRecord = $StateRecords[$sourceId]
        }
    } elseif ($null -ne $StateRecords.PSObject.Properties[$sourceId]) {
        $matchedRecord = $StateRecords.PSObject.Properties[$sourceId].Value
    }

    if ($null -eq $matchedRecord) {
        return $false
    }

    if ($null -ne $CalendarEvent.PSObject.Properties['id'] -and
        -not [string]::IsNullOrWhiteSpace([string]$CalendarEvent.id)) {
        $eventId = [string]$CalendarEvent.id
        $stateGraphId = $null
        if ($matchedRecord -is [System.Collections.IDictionary] -and $matchedRecord.Contains('graphEventId')) {
            $stateGraphId = [string]$matchedRecord['graphEventId']
        } elseif ($null -ne $matchedRecord.PSObject.Properties['graphEventId']) {
            $stateGraphId = [string]$matchedRecord.graphEventId
        }

        if (-not [string]::IsNullOrWhiteSpace($stateGraphId) -and
            -not $eventId.Equals($stateGraphId, [System.StringComparison]::Ordinal)) {
            return $false
        }
    }

    return $true
}

function Get-RoomCalendarEventById {
    <#
    .SYNOPSIS
        Retrieves a single calendar event by its Graph ID with expanded MAPI ownership properties.
    .DESCRIPTION
        Queries GET /users/{mailbox}/events/{eventId} with $expand on ActiveNetSyncOwned and ActiveNetSourceId.
        Returns $null if the event returns HTTP 404 Not Found.
    .PARAMETER AccessToken
        Bearer token (SecureString or string).
    .PARAMETER Mailbox
        Target room mailbox UPN/address.
    .PARAMETER EventId
        The Graph event ID to retrieve.
    .PARAMETER TimeZone
        Prefer outlook.timezone header value. Defaults to 'Central Standard Time'.
    .OUTPUTS
        PSCustomObject representing the Graph event, or $null if not found (404).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EventId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = 'Central Standard Time'
    )

    $plainToken = ConvertFrom-TokenToPlainInternal -AccessToken $AccessToken
    $encodedMailbox = [System.Uri]::EscapeDataString($Mailbox)
    $encodedEventId = [System.Uri]::EscapeDataString($EventId)
    $expandFilter = "id eq '$script:PropIdSyncOwned' or id eq '$script:PropIdSourceId'"
    $encodedExpand = [System.Uri]::EscapeDataString($expandFilter)

    $uri = "https://graph.microsoft.com/v1.0/users/$encodedMailbox/events/$encodedEventId`?`$expand=singleValueExtendedProperties(`$filter=$encodedExpand)"

    $headers = @{
        'Authorization' = "Bearer $plainToken"
        'Accept'        = 'application/json'
        'Prefer'        = "outlook.timezone=""$TimeZone"""
    }

    try {
        return (Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop)
    } catch {
        $statusCode = 0
        if ($null -ne $_.Exception -and $null -ne $_.Exception.PSObject.Properties['Response'] -and $null -ne $_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -eq 404 -or $_.ToString() -match '\b404\b') {
            return $null
        }
        throw
    }
}

function Get-RoomCalendarView {
    <#
    .SYNOPSIS
        Retrieves all calendar events in the specified window using calendarView paging and Prefer timezone header.
    .DESCRIPTION
        Queries GET /users/{mailbox}/calendarView with startDateTime, endDateTime, Prefer: outlook.timezone,
        and $expand on singleValueExtendedProperties. Follows @odata.nextLink until all pages are retrieved.
    .PARAMETER AccessToken
        Bearer token (SecureString or string).
    .PARAMETER Mailbox
        Target room mailbox UPN/address.
    .PARAMETER StartDateTime
        Start of the calendar view window.
    .PARAMETER EndDateTime
        End of the calendar view window.
    .PARAMETER TimeZone
        Windows timezone identifier for the Prefer header. Defaults to 'Central Standard Time'.
    .PARAMETER PageSize
        Maximum records per page ($top). Defaults to 250.
    .OUTPUTS
        PSCustomObject[] array of Graph event objects.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = 'Central Standard Time',

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 999)]
        [int]$PageSize = 250
    )

    if ($EndDateTime -le $StartDateTime) {
        throw "EndDateTime must be greater than StartDateTime."
    }

    $plainToken = ConvertFrom-TokenToPlainInternal -AccessToken $AccessToken
    $encodedMailbox = [System.Uri]::EscapeDataString($Mailbox)
    $startIso = $StartDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $endIso   = $EndDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)

    $selectFields = 'id,subject,start,end,showAs,isCancelled,organizer,changeKey,isAllDay'
    $expandFilter = "id eq '$script:PropIdSyncOwned' or id eq '$script:PropIdSourceId'"
    $encodedExpand = [System.Uri]::EscapeDataString($expandFilter)

    $nextUri = "https://graph.microsoft.com/v1.0/users/$encodedMailbox/calendarView?startDateTime=$startIso&endDateTime=$endIso&`$top=$PageSize&`$select=$selectFields&`$expand=singleValueExtendedProperties(`$filter=$encodedExpand)"

    $headers = @{
        'Authorization' = "Bearer $plainToken"
        'Accept'        = 'application/json'
        'Prefer'        = "outlook.timezone=""$TimeZone"""
    }

    $events = [System.Collections.Generic.List[PSCustomObject]]::new()

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $resp = Invoke-RestMethod -Uri $nextUri -Method Get -Headers $headers -ErrorAction Stop
        if ($null -ne $resp -and $null -ne $resp.PSObject.Properties['value'] -and $null -ne $resp.value) {
            foreach ($ev in @($resp.value)) {
                if ($null -ne $ev) {
                    $events.Add($ev)
                }
            }
        }

        if ($null -ne $resp -and $null -ne $resp.PSObject.Properties['@odata.nextLink'] -and -not [string]::IsNullOrWhiteSpace([string]$resp.'@odata.nextLink')) {
            $nextUri = [string]$resp.'@odata.nextLink'
        } else {
            $nextUri = $null
        }
    }

    return $events.ToArray()
}

function New-RoomCalendarEvent {
    <#
    .SYNOPSIS
        Creates a plain occupancy event on the room calendar stamped with MAPI ownership metadata.
    .DESCRIPTION
        Enforces Hard Constraint 6: attendees is always empty (@()), isOnlineMeeting is always $false,
        responseRequested is always $false. Stamps ActiveNetSyncOwned = "True" and ActiveNetSourceId.
        Note: Defined in Stage 3B per design contract; not invoked until Stage 3D/3E.
    .PARAMETER AccessToken
        Bearer token (SecureString or string).
    .PARAMETER Mailbox
        Target room mailbox UPN/address.
    .PARAMETER Subject
        Outlook subject string (e.g., "[AN] Event Name").
    .PARAMETER StartDateTime
        Effective start time in local timezone.
    .PARAMETER EndDateTime
        Effective end time in local timezone.
    .PARAMETER ShowAs
        Availability status ('busy' or 'tentative').
    .PARAMETER SourceScheduleId
        Deterministic ACTIVENet composite key to stamp in ActiveNetSourceId.
    .PARAMETER TimeZone
        Windows timezone identifier. Defaults to 'Central Standard Time'.
    .OUTPUTS
        PSCustomObject representing the created Graph event.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Unattended service mutation defined per design contract')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $true)]
        [ValidateSet('busy', 'tentative', 'free')]
        [string]$ShowAs,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceScheduleId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = 'Central Standard Time',

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$BodyHtml = ''
    )

    $plainToken = ConvertFrom-TokenToPlainInternal -AccessToken $AccessToken
    $encodedMailbox = [System.Uri]::EscapeDataString($Mailbox)
    $uri = "https://graph.microsoft.com/v1.0/users/$encodedMailbox/calendar/events"

    $effectiveBody = if (-not [string]::IsNullOrWhiteSpace($BodyHtml)) {
        $BodyHtml
    } else {
        '<p>ACTIVENet Occupancy Projection. Managed automatically. Do not edit directly.</p>'
    }

    $payload = [ordered]@{
        subject           = $Subject
        showAs            = $ShowAs
        attendees         = @()
        isOnlineMeeting   = $false
        responseRequested = $false
        body              = [ordered]@{
            contentType = 'HTML'
            content     = $effectiveBody
        }
        start             = [ordered]@{
            dateTime = $StartDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            timeZone = $TimeZone
        }
        end               = [ordered]@{
            dateTime = $EndDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            timeZone = $TimeZone
        }
        singleValueExtendedProperties = @(
            [ordered]@{
                id    = $script:PropIdSyncOwned
                value = 'True'
            },
            [ordered]@{
                id    = $script:PropIdSourceId
                value = $SourceScheduleId
            }
        )
    } | ConvertTo-Json -Depth 5

    $headers = @{
        'Authorization' = "Bearer $plainToken"
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }

    return (Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payload -ErrorAction Stop)
}

function Set-RoomCalendarEvent {
    <#
    .SYNOPSIS
        Updates an existing sync-owned calendar event after re-reading and re-verifying MAPI ownership.
    .DESCRIPTION
        Enforces Hard Constraints 1, 4, and 6: Re-reads the target event from Graph before PATCH,
        verifies ownership via Test-SyncOwnership against StateRecords and ExpectedSourceId,
        and aborts if ownership is not positively proven.
        Note: Defined in Stage 3B per design contract; not invoked until Stage 3D/3E.
    .PARAMETER AccessToken
        Bearer token (SecureString or string).
    .PARAMETER Mailbox
        Target room mailbox UPN/address.
    .PARAMETER EventId
        Target Graph event ID to update.
    .PARAMETER StateRecords
        Local state records dictionary/hashtable for ownership verification.
    .PARAMETER ExpectedSourceId
        Expected ActiveNetSourceId for the event.
    .PARAMETER Subject
        Updated subject string.
    .PARAMETER StartDateTime
        Updated effective start time.
    .PARAMETER EndDateTime
        Updated effective end time.
    .PARAMETER ShowAs
        Updated availability state ('busy' or 'tentative').
    .PARAMETER TimeZone
        Windows timezone identifier. Defaults to 'Central Standard Time'.
    .OUTPUTS
        PSCustomObject representing the updated Graph event.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Unattended service mutation guarded by mandatory MAPI ownership re-verification')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EventId,

        [Parameter(Mandatory = $true)]
        [object]$StateRecords,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedSourceId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $true)]
        [ValidateSet('busy', 'tentative', 'free')]
        [string]$ShowAs,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = 'Central Standard Time',

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$BodyHtml = ''
    )

    # Hard Constraint 4: Re-read target event's MAPI properties and re-verify ownership before PATCH
    $liveEvent = Get-RoomCalendarEventById -AccessToken $AccessToken -Mailbox $Mailbox -EventId $EventId -TimeZone $TimeZone
    if ($null -eq $liveEvent) {
        throw "Cannot PATCH event '$EventId': Event not found (404) during pre-mutation ownership re-verification."
    }

    $isOwned = Test-SyncOwnership -CalendarEvent $liveEvent -StateRecords $StateRecords -ExpectedSourceId $ExpectedSourceId
    if (-not $isOwned) {
        throw "SECURITY VIOLATION PREVENTED: Refusing to PATCH event '$EventId' because positive MAPI and state ownership verification failed."
    }

    $plainToken = ConvertFrom-TokenToPlainInternal -AccessToken $AccessToken
    $encodedMailbox = [System.Uri]::EscapeDataString($Mailbox)
    $encodedEventId = [System.Uri]::EscapeDataString($EventId)
    $uri = "https://graph.microsoft.com/v1.0/users/$encodedMailbox/events/$encodedEventId"

    $payloadObj = [ordered]@{
        subject           = $Subject
        showAs            = $ShowAs
        attendees         = @()
        isOnlineMeeting   = $false
        responseRequested = $false
        start             = [ordered]@{
            dateTime = $StartDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            timeZone = $TimeZone
        }
        end               = [ordered]@{
            dateTime = $EndDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            timeZone = $TimeZone
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($BodyHtml)) {
        $payloadObj['body'] = [ordered]@{
            contentType = 'HTML'
            content     = $BodyHtml
        }
    }
    $payload = $payloadObj | ConvertTo-Json -Depth 5

    $headers = @{
        'Authorization' = "Bearer $plainToken"
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }

    return (Invoke-RestMethod -Uri $uri -Method Patch -Headers $headers -Body $payload -ErrorAction Stop)
}

function Remove-RoomCalendarEvent {
    <#
    .SYNOPSIS
        Deletes a sync-owned calendar event after re-reading and re-verifying MAPI ownership.
    .DESCRIPTION
        Enforces Hard Constraints 1 and 4: Re-reads the target event from Graph before DELETE,
        verifies ownership via Test-SyncOwnership against StateRecords and ExpectedSourceId,
        and aborts if ownership is not positively proven.
        Note: Defined in Stage 3B per design contract; not invoked until Stage 3D/3E.
    .PARAMETER AccessToken
        Bearer token (SecureString or string).
    .PARAMETER Mailbox
        Target room mailbox UPN/address.
    .PARAMETER EventId
        Target Graph event ID to delete.
    .PARAMETER StateRecords
        Local state records dictionary/hashtable for ownership verification.
    .PARAMETER ExpectedSourceId
        Expected ActiveNetSourceId for the event.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Unattended service mutation guarded by mandatory MAPI ownership re-verification')]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EventId,

        [Parameter(Mandatory = $true)]
        [object]$StateRecords,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedSourceId
    )

    # Hard Constraint 4: Re-read target event's MAPI properties and re-verify ownership before DELETE
    $liveEvent = Get-RoomCalendarEventById -AccessToken $AccessToken -Mailbox $Mailbox -EventId $EventId
    if ($null -eq $liveEvent) {
        return
    }

    $isOwned = Test-SyncOwnership -CalendarEvent $liveEvent -StateRecords $StateRecords -ExpectedSourceId $ExpectedSourceId
    if (-not $isOwned) {
        throw "SECURITY VIOLATION PREVENTED: Refusing to DELETE event '$EventId' because positive MAPI and state ownership verification failed."
    }

    $plainToken = ConvertFrom-TokenToPlainInternal -AccessToken $AccessToken
    $encodedMailbox = [System.Uri]::EscapeDataString($Mailbox)
    $encodedEventId = [System.Uri]::EscapeDataString($EventId)
    $uri = "https://graph.microsoft.com/v1.0/users/$encodedMailbox/events/$encodedEventId"

    $headers = @{
        'Authorization' = "Bearer $plainToken"
        'Accept'        = 'application/json'
    }

    [void](Invoke-RestMethod -Uri $uri -Method Delete -Headers $headers -ErrorAction Stop)
}

Export-ModuleMember -Function @(
    'Connect-GraphApplication',
    'Get-GraphEventExtendedProperty',
    'Test-SyncOwnership',
    'Get-RoomCalendarEventById',
    'Get-RoomCalendarView',
    'New-RoomCalendarEvent',
    'Set-RoomCalendarEvent',
    'Remove-RoomCalendarEvent'
)
