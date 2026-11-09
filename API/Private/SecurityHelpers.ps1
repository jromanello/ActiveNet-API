<#
.SYNOPSIS
    Internal security and memory-safety helpers for ActiveNetAPI module.
.DESCRIPTION
    Provides memory-safe SecureString extraction and unmanaged BSTR zero-freeing
    semantics compatible with both Windows PowerShell 5.1 (Full CLR) and PowerShell 7+ (.NET Core).
#>

function ConvertFrom-SecureOrPlainString {
    <#
    .SYNOPSIS
        Extracts plain string from SecureString or string with zero-free BSTR memory safety.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($null -eq $Value) {
        throw "Value cannot be null."
    }

    if ($Value -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    } elseif ($Value -is [string]) {
        return [string]$Value
    } else {
        throw "Expected [System.Security.SecureString] or [string], but received [$($Value.GetType().FullName)]."
    }
}
