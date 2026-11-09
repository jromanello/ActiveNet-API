#Requires -Version 7.0
<#
.SYNOPSIS
    Registers or updates the nightly Windows Scheduled Task for ACTIVENet to M365 Calendar Sync.
.DESCRIPTION
    Configures the 'ActiveNet-M365-CalendarSync' scheduled task per ARCHITECTURE.md Section 16:
    - Trigger: Daily at 02:00 AM local (Central) time.
    - Action: pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<InstallRoot>\src\Sync-ActiveNetToM365.ps1" -ConfigPath "..\config\config.json"
    - Working Directory: <InstallRoot>\src
    - Settings: Stop if running longer than 1 hour; IgnoreNew (do not start a concurrent instance); StartWhenAvailable.
    - Principal: Runs under the dedicated service account whether logged on or not.
.PARAMETER InstallRoot
    Root installation directory on the Windows Server host. Defaults to C:\Scripts\ActiveNetRoomSync.
.PARAMETER ServiceAccount
    The service account identity (e.g., 'NPD\activenet-sync' or 'activenet-sync').
.PARAMETER TaskName
    Name of the scheduled task. Defaults to 'ActiveNet-M365-CalendarSync'.
.PARAMETER DailyRunTime
    Daily trigger time. Defaults to '02:00AM'.
.PARAMETER PwshPath
    Path to PowerShell 7 executable. Defaults to C:\Program Files\PowerShell\7\pwsh.exe.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallRoot = 'C:\Scripts\ActiveNetRoomSync',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccount,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'ActiveNet-M365-CalendarSync',

    [Parameter(Mandatory = $false)]
    [datetime]$DailyRunTime = ([datetime]::Today.AddHours(2)),

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PwshPath = 'C:\Program Files\PowerShell\7\pwsh.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $PwshPath -PathType Leaf)) {
    $cmdPwsh = Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue
    if ($null -ne $cmdPwsh -and -not [string]::IsNullOrWhiteSpace($cmdPwsh.Source)) {
        $PwshPath = $cmdPwsh.Source
    } else {
        throw "PowerShell 7 executable not found at '$PwshPath'."
    }
}

$srcDir     = Join-Path -Path $InstallRoot -ChildPath 'src'
$scriptPath = Join-Path -Path $srcDir -ChildPath 'Sync-ActiveNetToM365.ps1'
$configPath = Join-Path -Path $InstallRoot -ChildPath 'config\config.json'

if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Orchestrator script not found at '$scriptPath'."
}
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Configuration file not found at '$configPath'."
}

$actionArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`" -ConfigPath `"..\config\config.json`""

$action   = New-ScheduledTaskAction -Execute $PwshPath -Argument $actionArgs -WorkingDirectory $srcDir
$trigger  = New-ScheduledTaskTrigger -Daily -At $DailyRunTime
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

if ($PSCmdlet.ShouldProcess($TaskName, "Register Scheduled Task under '$ServiceAccount' at $($DailyRunTime.ToString('HH:mm'))")) {
    $isGmsaOrSystem = ($ServiceAccount -match '\$$' -or $ServiceAccount -match '^(?i)(NT AUTHORITY\\SYSTEM|SYSTEM|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService)$')
    if ($isGmsaOrSystem) {
        $logonType = if ($ServiceAccount -match '\$$') { 'Password' } else { 'ServiceAccount' }
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType $logonType -RunLevel Highest
        [void](Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Description 'Nightly one-way occupancy synchronization from ACTIVENet Facility Management to Microsoft 365 Room Mailbox.' `
            -Force)
    } else {
        $secPass = Read-Host -Prompt "Enter password for service account '$ServiceAccount' (to run whether user is logged on or not)" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        try {
            $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [void](Register-ScheduledTask `
                -TaskName $TaskName `
                -Action $action `
                -Trigger $trigger `
                -Settings $settings `
                -User $ServiceAccount `
                -Password $plainPass `
                -RunLevel Highest `
                -Description 'Nightly one-way occupancy synchronization from ACTIVENet Facility Management to Microsoft 365 Room Mailbox.' `
                -Force)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    Write-Information -MessageData "Successfully registered scheduled task '$TaskName' under '$ServiceAccount' to run daily at $($DailyRunTime.ToString('hh:mm tt'))." -InformationAction Continue
}
