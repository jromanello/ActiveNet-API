function New-DynamicDigitalSignature {
    <#
    .SYNOPSIS
        Generates a dynamic digital signature for API requests.
    .DESCRIPTION
        This function generates a SHA-256 hash based digital signature by combining the API key, shared secret key, and current timestamp.
    .PARAMETER ApiKey
        Your API key. This parameter is required.
    .PARAMETER SharedSecretKey
        Your shared secret key. This parameter is required.
    .OUTPUTS
        Returns a string representing the digital signature in hexadecimal.
    .EXAMPLE
        PS> $signature = New-DynamicDigitalSignature -ApiKey 'your_api_key' -SharedSecretKey 'your_shared_secret_key'
    .EXAMPLE
        PS> New-DynamicDigitalSignature -ApiKey $apiKey -SharedSecretKey $sharedSecretKey
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$SharedSecretKey
    )

    #   Get timestamp in epoch seconds
    $timestamp = [int64][double]::Parse((Get-Date -UFormat %s))

    #   Concatenate signature parts
    $concatenate = $apiKey + $sharedSecretKey + $timestamp

    #   Hash and covert to hexadecimal string
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($concatenate)
    $sha256 = [System.Security.Cryptography.SHA256Managed]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $hexString = [System.BitConverter]::ToString($hashBytes) -replace '-',''

    return $hexString
}