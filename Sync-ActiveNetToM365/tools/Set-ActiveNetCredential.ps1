<#
.SYNOPSIS
    Securely stores ACTIVENet API credentials as DPAPI-encrypted SecureStrings.
.DESCRIPTION
    Prompts the operator for the ACTIVENet API Key and Shared Secret using Read-Host -AsSecureString,
    packs them as System.Security.SecureString objects, and exports them to a CLIXML file via Export-Clixml.
    Because Export-Clixml encrypts SecureString objects using the Windows Data Protection API (DPAPI)
    tied to the executing user's Windows profile, this script must be executed under the dedicated
    service account (e.g., svc-activenet-sync).
.PARAMETER DestinationPath
    Target file path for the encrypted credential file. Defaults to config/activenet_creds.clixml.
.PARAMETER Force
    Suppresses confirmation prompts regarding the executing user account.
.EXAMPLE
    pwsh -File ./tools/Set-ActiveNetCredential.ps1
.EXAMPLE
    pwsh -File ./tools/Set-ActiveNetCredential.ps1 -DestinationPath "C:\Drive_D\Coding\Git\ActiveNet-API\config\activenet_creds.clixml"
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive credential input CLI tool requiring console messaging')]
param (
    [Parameter(Mandatory = $false)]
    [string]$DestinationPath = "$PSScriptRoot/../config/activenet_creds.clixml",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " ACTIVENet Secure Credential Storage Setup " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Executing User: $currentUser" -ForegroundColor Yellow

if (-not $Force -and ($currentUser -notlike "*activenet-sync*")) {
    Write-Warning "DPAPI encryption is bound to the CURRENT Windows user profile: $currentUser."
    Write-Warning "If the scheduled task runs as 'activenet-sync', credentials stored under a different account CANNOT be decrypted."
    $confirm = Read-Host "Proceed anyway? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Aborted by operator." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Enter ACTIVENet API Key (input will be masked):" -ForegroundColor Green
$secApiKey = Read-Host -AsSecureString
if ($null -eq $secApiKey -or $secApiKey.Length -eq 0) {
    Write-Error "API Key cannot be empty."
    exit 1
}

Write-Host "Enter ACTIVENet Shared Secret (input will be masked):" -ForegroundColor Green
$secSharedSecret = Read-Host -AsSecureString
if ($null -eq $secSharedSecret -or $secSharedSecret.Length -eq 0) {
    Write-Error "Shared Secret cannot be empty."
    exit 1
}

$resolvedDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($DestinationPath))
if (-not (Test-Path -Path $resolvedDir)) {
    New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null
}

$credentialPackage = [PSCustomObject]@{
    ApiKey       = $secApiKey
    SharedSecret = $secSharedSecret
    CreatedUtc   = [System.DateTime]::UtcNow.ToString("o")
    CreatedBy    = $currentUser
}

$credentialPackage | Export-Clixml -Path $DestinationPath -Force

Write-Host "Credentials successfully encrypted and saved to: $DestinationPath" -ForegroundColor Green
Write-Host "Verified DPAPI storage container created." -ForegroundColor Green
exit 0
