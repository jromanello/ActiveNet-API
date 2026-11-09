<#
.SYNOPSIS
    Generates a dynamic SHA-256 digital signature for ACTIVENet API requests.
.DESCRIPTION
    This function generates a SHA-256 hash based digital signature by combining the API key,
    shared secret key, and Unix timestamp in epoch seconds (API_KEY + SHARED_SECRET + EPOCH_SECONDS).
    
    Enterprise hardening features:
    - Accepts credentials as either [System.Security.SecureString] or standard [string].
    - Guarantees immediate zero-freeing of unmanaged BSTR memory via [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR.
    - Uses modern [System.Security.Cryptography.SHA256]::Create() (no deprecated SHA256Managed).
    - Returns a deterministic 64-character lowercase hexadecimal hash.
    - Preserves backward-compatible parameter names and aliases (-ApiKey, -Secret, -API_Key, -Shared_Secret, -SharedSecretKey).
.PARAMETER ApiKey
    Your ACTIVENet API key as [System.Security.SecureString] or [string]. This parameter is required.
.PARAMETER Secret
    Your ACTIVENet shared secret key as [System.Security.SecureString] or [string]. This parameter is required.
.PARAMETER EpochSeconds
    Optional Unix timestamp in epoch seconds. Defaults to current UTC epoch seconds ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()).
.OUTPUTS
    [string] Returns a 64-character lowercase hexadecimal SHA-256 signature string.
.EXAMPLE
    PS> $signature = New-DynamicDigitalSignature -ApiKey 'your_api_key' -Secret 'your_shared_secret'
.EXAMPLE
    PS> $signature = New-DynamicDigitalSignature -ApiKey $secApiKey -Secret $secSharedSecret
.EXAMPLE
    PS> # Using legacy v1 parameter names
    PS> $signature = New-DynamicDigitalSignature -API_Key 'your_api_key' -SharedSecretKey 'your_shared_secret'
#>
function New-DynamicDigitalSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('API_Key', 'Key')]
        [object]$ApiKey,

        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('SharedSecretKey', 'Shared_Secret', 'SharedSecret')]
        [object]$Secret,

        [Parameter(Mandatory = $false, Position = 2)]
        [Alias('timestamp')]
        [int64]$EpochSeconds = 0
    )

    # Self-contained helper fallback for standalone script execution
    $extractString = {
        param([object]$val, [string]$paramName)
        if ($null -eq $val) {
            throw "$paramName cannot be null."
        }
        if ($val -is [System.Security.SecureString]) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($val)
            try {
                return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                if ($bstr -ne [System.IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }
        } elseif ($val -is [string]) {
            return [string]$val
        } else {
            throw "$paramName must be a [System.Security.SecureString] or [string], received [$($val.GetType().FullName)]."
        }
    }

    $plainKey = & $extractString $ApiKey 'ApiKey'
    $plainSecret = & $extractString $Secret 'Secret'

    if ($EpochSeconds -le 0) {
        $EpochSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }

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
