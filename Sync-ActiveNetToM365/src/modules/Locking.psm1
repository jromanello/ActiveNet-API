#Requires -Version 7.0
Set-StrictMode -Version Latest

function Test-LockProcessRunning {
    <#
    .SYNOPSIS
        Tests whether a process with the specified PID is currently running on the host.
    .DESCRIPTION
        Queries the local process table for the given ProcessId. Returns $true if the process
        exists and has not exited; returns $false otherwise.
    .PARAMETER ProcessId
        The numeric process ID (PID) to check.
    .OUTPUTS
        System.Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    if ($ProcessId -le 0) {
        return $false
    }

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -ne $proc) {
            return $true
        }
    } catch {
        return $false
    }

    return $false
}

function Lock-SyncProcess {
    <#
    .SYNOPSIS
        Acquires a non-blocking exclusive lock on state/sync.lock containing the owning PID.
    .DESCRIPTION
        Attempts to acquire an exclusive write lock on the specified lock file. If the lock file
        already exists, reads the recorded PID. If that PID is still running, refuses to acquire
        the lock and returns $null. If the recorded PID is no longer running (stale lock after crash
        or reboot), reclaims the lock file, writes the current PID, and holds the FileStream open
        with FileShare.Read so concurrent processes can inspect the PID but cannot write.
    .PARAMETER LockFilePath
        Full path to the lock file (e.g., state/sync.lock).
    .PARAMETER ProcessId
        Optional PID override (defaults to current $PID). Useful for unit testing.
    .OUTPUTS
        PSCustomObject representing the active lock handle, or $null if the lock is held by a running process.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LockFilePath,

        [Parameter(Mandatory = $false)]
        [int]$ProcessId = $PID
    )

    $parentDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($LockFilePath))
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -Path $parentDir -PathType Container)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $reclaimedStaleLock = $false

    if (Test-Path -Path $LockFilePath -PathType Leaf) {
        $existingPid = 0
        try {
            $rawContent = Get-Content -Path $LockFilePath -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($rawContent)) {
                $trimmed = $rawContent.Trim()
                if ($trimmed.StartsWith('{')) {
                    $parsedLock = $trimmed | ConvertFrom-Json -ErrorAction Stop
                    if ($null -ne $parsedLock.PSObject.Properties['pid']) {
                        $existingPid = [int]$parsedLock.pid
                    }
                } else {
                    [void][int]::TryParse($trimmed, [ref]$existingPid)
                }
            }
        } catch {
            # If unreadable or locked exclusively without read share, treat as locked unless stream open succeeds
            $existingPid = -1
        }

        if ($existingPid -gt 0) {
            $isRunning = Test-LockProcessRunning -ProcessId $existingPid
            if ($isRunning) {
                return $null
            }
            $reclaimedStaleLock = $true
        }
    }

    try {
        $fileStream = [System.IO.File]::Open(
            $LockFilePath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::Read
        )
    } catch [System.IO.IOException] {
        return $null
    }

    try {
        $fileStream.SetLength(0)
        $lockPayload = [ordered]@{
            pid         = $ProcessId
            acquiredUtc = [datetime]::UtcNow.ToString('o')
            hostName    = [Environment]::MachineName
        } | ConvertTo-Json -Compress

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($lockPayload)
        $fileStream.Write($bytes, 0, $bytes.Length)
        $fileStream.Flush()

        return [PSCustomObject]@{
            LockFilePath       = [System.IO.Path]::GetFullPath($LockFilePath)
            ProcessId          = $ProcessId
            Stream             = $fileStream
            ReclaimedStaleLock = $reclaimedStaleLock
            AcquiredUtc        = [datetime]::UtcNow.ToString('o')
        }
    } catch {
        $fileStream.Dispose()
        throw
    }
}

function Unlock-SyncProcess {
    <#
    .SYNOPSIS
        Releases the exclusive process lock and removes the lock file.
    .DESCRIPTION
        Closes and disposes the underlying FileStream and deletes the state/sync.lock file.
        Designed to be called inside a finally block to guarantee lock cleanup.
    .PARAMETER LockHandle
        The lock object returned by Lock-SyncProcess.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$LockHandle
    )

    if ($null -eq $LockHandle) {
        return
    }

    if ($null -ne $LockHandle.PSObject.Properties['Stream'] -and $null -ne $LockHandle.Stream) {
        try {
            $LockHandle.Stream.Flush()
            $LockHandle.Stream.Close()
            $LockHandle.Stream.Dispose()
        } catch {
            Write-Verbose "Stream disposal warning: $_"
        }
    }

    if ($null -ne $LockHandle.PSObject.Properties['LockFilePath'] -and
        -not [string]::IsNullOrWhiteSpace($LockHandle.LockFilePath) -and
        (Test-Path -Path $LockHandle.LockFilePath -PathType Leaf)) {
        try {
            Remove-Item -Path $LockHandle.LockFilePath -Force -ErrorAction Stop
        } catch {
            Write-Verbose "Lock file removal warning: $_"
        }
    }
}

Export-ModuleMember -Function @(
    'Test-LockProcessRunning',
    'Lock-SyncProcess',
    'Unlock-SyncProcess'
)
