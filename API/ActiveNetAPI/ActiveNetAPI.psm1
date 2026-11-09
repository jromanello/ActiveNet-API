#Requires -Version 5.1
Set-StrictMode -Version Latest

# Dot-source private helper functions
$privateHelpers = Join-Path -Path $PSScriptRoot -ChildPath 'Private\SecurityHelpers.ps1'
if (Test-Path -LiteralPath $privateHelpers) {
    . $privateHelpers
}

# Dot-source public module functions
$publicDir = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
if (Test-Path -LiteralPath $publicDir) {
    Get-ChildItem -Path $publicDir -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
} else {
    # Fallback if scripts are directly in module root
    $sigScript = Join-Path -Path $PSScriptRoot -ChildPath 'New-DynamicDigitalSignature.ps1'
    if (Test-Path -LiteralPath $sigScript) { . $sigScript }

    $invScript = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-ActiveNetAPI.ps1'
    if (Test-Path -LiteralPath $invScript) { . $invScript }
}

# Define command aliases
Set-Alias -Name 'Invoke-ANAPI' -Value 'Invoke-ActiveNetAPI' -Description 'Alias for Invoke-ActiveNetAPI'
Set-Alias -Name 'New-ANDigitalSignature' -Value 'New-DynamicDigitalSignature' -Description 'Alias for New-DynamicDigitalSignature'

Export-ModuleMember `
    -Function @('Invoke-ActiveNetAPI', 'New-DynamicDigitalSignature') `
    -Alias @('Invoke-ANAPI', 'New-ANDigitalSignature')
