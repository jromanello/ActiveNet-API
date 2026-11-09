#Requires -Version 7.0
Set-StrictMode -Version Latest

function Test-IntervalOverlap {
    <#
    .SYNOPSIS
        Evaluates whether two half-open time intervals [StartA, EndA) and [StartB, EndB) overlap.
    .DESCRIPTION
        Applies half-open interval semantics per ARCHITECTURE.md Section 11.2:
        max(StartA, StartB) < min(EndA, EndB).
        Abutting boundaries where EndA == StartB or EndB == StartA return $false (no conflict).
    .PARAMETER StartA
        Start of interval A.
    .PARAMETER EndA
        End of interval A.
    .PARAMETER StartB
        Start of interval B.
    .PARAMETER EndB
        End of interval B.
    .OUTPUTS
        System.Boolean. $true if intervals overlap; $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartA,

        [Parameter(Mandatory = $true)]
        [datetime]$EndA,

        [Parameter(Mandatory = $true)]
        [datetime]$StartB,

        [Parameter(Mandatory = $true)]
        [datetime]$EndB
    )

    $maxStart = if ($StartA -gt $StartB) { $StartA } else { $StartB }
    $minEnd   = if ($EndA -lt $EndB) { $EndA } else { $EndB }

    return ($maxStart -lt $minEnd)
}

function Get-ConflictIdentityKey {
    <#
    .SYNOPSIS
        Computes the deterministic SHA-256 ConflictKey for notification deduplication.
    .DESCRIPTION
        Calculates SHA256(SourceScheduleId + OutlookEventId + ChangeKey) as a 64-character
        lowercase hexadecimal string per ARCHITECTURE.md Section 11.3.
    .PARAMETER SourceScheduleId
        The ACTIVENet composite schedule key.
    .PARAMETER OutlookEventId
        The Graph event ID of the conflicting Outlook-native meeting.
    .PARAMETER ChangeKey
        The Graph changeKey of the conflicting Outlook-native meeting.
    .OUTPUTS
        System.String. 64-character lowercase hex SHA-256 digest.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceScheduleId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutlookEventId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ChangeKey = ''
    )

    $payload = "$SourceScheduleId$OutlookEventId$ChangeKey"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
}

function Find-CalendarConflict {
    <#
    .SYNOPSIS
        Detects scheduling conflicts between an ACTIVENet NormalizedOccupancyEvent and Outlook-native meetings.
    .DESCRIPTION
        Compares the effective occupancy window [EffectiveStart, EffectiveEnd) of a normalized
        ACTIVENet event against Outlook-native calendar events using half-open interval semantics.
        Ignores cancelled Outlook meetings and any event carrying ActiveNetSyncOwned == 'True'.
    .PARAMETER NormalizedEvent
        The canonical NormalizedOccupancyEvent object to evaluate.
    .PARAMETER OutlookNativeEvents
        Array of Outlook-native Graph calendar event objects.
    .OUTPUTS
        PSCustomObject[] array of detected conflict records.
    #>
    [CmdletBinding()]
    [Alias('Find-CalendarConflicts')]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$NormalizedEvent,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [PSCustomObject[]]$OutlookNativeEvents = @()
    )

    $conflicts = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($null -eq $OutlookNativeEvents -or $OutlookNativeEvents.Count -eq 0) {
        return $conflicts.ToArray()
    }

    $anStart = [datetime]$NormalizedEvent.EffectiveStart
    $anEnd   = [datetime]$NormalizedEvent.EffectiveEnd

    foreach ($outlookEvent in $OutlookNativeEvents) {
        if ($null -eq $outlookEvent) {
            continue
        }

        # Skip cancelled Outlook events
        if ($null -ne $outlookEvent.PSObject.Properties['isCancelled'] -and [bool]$outlookEvent.isCancelled) {
            continue
        }

        # Defense-in-depth: never treat an event carrying ActiveNetSyncOwned == 'True' as an Outlook-native conflict
        $hasSyncOwnedTag = $false
        if ($null -ne $outlookEvent.PSObject.Properties['singleValueExtendedProperties'] -and
            $null -ne $outlookEvent.singleValueExtendedProperties) {
            foreach ($prop in @($outlookEvent.singleValueExtendedProperties)) {
                if ($null -ne $prop -and
                    $null -ne $prop.PSObject.Properties['id'] -and
                    ([string]$prop.id) -match '(?i)ActiveNetSyncOwned' -and
                    $null -ne $prop.PSObject.Properties['value'] -and
                    ([string]$prop.value) -ceq 'True') {
                    $hasSyncOwnedTag = $true
                    break
                }
            }
        }
        if ($hasSyncOwnedTag) {
            continue
        }

        # Extract start and end DateTime
        $rawStart = $null
        $rawEnd   = $null
        if ($null -ne $outlookEvent.PSObject.Properties['start'] -and $null -ne $outlookEvent.start) {
            if ($outlookEvent.start -is [datetime]) {
                $rawStart = $outlookEvent.start
            } elseif ($null -ne $outlookEvent.start.PSObject.Properties['dateTime']) {
                $rawStart = [datetime]::Parse([string]$outlookEvent.start.dateTime, [System.Globalization.CultureInfo]::InvariantCulture)
            }
        }
        if ($null -ne $outlookEvent.PSObject.Properties['end'] -and $null -ne $outlookEvent.end) {
            if ($outlookEvent.end -is [datetime]) {
                $rawEnd = $outlookEvent.end
            } elseif ($null -ne $outlookEvent.end.PSObject.Properties['dateTime']) {
                $rawEnd = [datetime]::Parse([string]$outlookEvent.end.dateTime, [System.Globalization.CultureInfo]::InvariantCulture)
            }
        }

        if ($null -eq $rawStart -or $null -eq $rawEnd) {
            continue
        }

        $overlaps = Test-IntervalOverlap -StartA $anStart -EndA $anEnd -StartB $rawStart -EndB $rawEnd
        if (-not $overlaps) {
            continue
        }

        $evId = if ($null -ne $outlookEvent.PSObject.Properties['id'] -and -not [string]::IsNullOrWhiteSpace([string]$outlookEvent.id)) {
            [string]$outlookEvent.id
        } else {
            'UNKNOWN_EVENT_ID'
        }

        $changeKey = if ($null -ne $outlookEvent.PSObject.Properties['changeKey'] -and $null -ne $outlookEvent.changeKey) {
            [string]$outlookEvent.changeKey
        } else {
            ''
        }

        $organizerEmail = ''
        $organizerName  = ''
        if ($null -ne $outlookEvent.PSObject.Properties['organizer'] -and
            $null -ne $outlookEvent.organizer -and
            $null -ne $outlookEvent.organizer.PSObject.Properties['emailAddress'] -and
            $null -ne $outlookEvent.organizer.emailAddress) {
            if ($null -ne $outlookEvent.organizer.emailAddress.PSObject.Properties['address'] -and $null -ne $outlookEvent.organizer.emailAddress.address) {
                $organizerEmail = [string]$outlookEvent.organizer.emailAddress.address
            }
            if ($null -ne $outlookEvent.organizer.emailAddress.PSObject.Properties['name'] -and $null -ne $outlookEvent.organizer.emailAddress.name) {
                $organizerName = [string]$outlookEvent.organizer.emailAddress.name
            }
        }

        $conflictKey = Get-ConflictIdentityKey `
            -SourceScheduleId ([string]$NormalizedEvent.SourceScheduleId) `
            -OutlookEventId $evId `
            -ChangeKey $changeKey

        $conflicts.Add([PSCustomObject]@{
            ConflictKey           = $conflictKey
            SourceScheduleId      = [string]$NormalizedEvent.SourceScheduleId
            OutlookEventId        = $evId
            OutlookChangeKey      = $changeKey
            OutlookOrganizerEmail = $organizerEmail
            OutlookOrganizerName  = $organizerName
            OutlookStart          = $rawStart
            OutlookEnd            = $rawEnd
        })
    }

    return $conflicts.ToArray()
}

Export-ModuleMember -Function @(
    'Test-IntervalOverlap',
    'Get-ConflictIdentityKey',
    'Find-CalendarConflict'
) -Alias @(
    'Find-CalendarConflicts'
)
