#Requires -Version 7.0
Set-StrictMode -Version Latest

function ConvertTo-Base64UrlString {
    <#
    .SYNOPSIS
        Encodes a byte array into an RFC 7515 Base64Url string.
    .DESCRIPTION
        Converts bytes to standard Base64, replaces '+' with '-', '/' with '_', and strips '=' padding.
    .PARAMETER Bytes
        The byte array to encode.
    .OUTPUTS
        System.String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    return ([Convert]::ToBase64String($Bytes) -replace '\+', '-' -replace '/', '_' -replace '=', '')
}

function ConvertFrom-SecureStringPlain {
    <#
    .SYNOPSIS
        Converts a SecureString to an in-memory string for transient cryptographic signing, freeing BSTR memory immediately.
    .DESCRIPTION
        Extracts the unmanaged BSTR from a SecureString and zeroes out the unmanaged memory buffer in a finally block.
        Never log or persist the returned value.
    .PARAMETER SecureValue
        The SecureString to unwrap.
    .OUTPUTS
        System.String.
    #>
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

function Get-ActiveNetCredential {
    <#
    .SYNOPSIS
        Loads DPAPI-encrypted ACTIVENet API credentials from a CLIXML file.
    .DESCRIPTION
        Imports the credential package from disk using Import-Clixml and verifies that both
        ApiKey and SharedSecret are stored as System.Security.SecureString objects (rejecting
        unencrypted plaintext strings).
    .PARAMETER ClixmlPath
        Path to the .clixml file created by tools/Set-ActiveNetCredential.ps1.
    .OUTPUTS
        PSCustomObject containing SecureString properties ApiKey and SharedSecret.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('CredentialFilePath')]
        [ValidateNotNullOrEmpty()]
        [string]$ClixmlPath
    )

    if (-not (Test-Path -Path $ClixmlPath -PathType Leaf)) {
        throw "ACTIVENet credential file not found at path: $ClixmlPath"
    }

    $imported = Import-Clixml -Path $ClixmlPath -ErrorAction Stop

    if ($null -eq $imported -or
        $null -eq $imported.PSObject.Properties['ApiKey'] -or
        $null -eq $imported.PSObject.Properties['SharedSecret']) {
        throw "ACTIVENet credential file is missing required 'ApiKey' or 'SharedSecret' properties."
    }

    if ($imported.ApiKey -isnot [System.Security.SecureString] -or
        $imported.SharedSecret -isnot [System.Security.SecureString]) {
        throw "Security policy violation: ApiKey and SharedSecret must be stored as DPAPI-encrypted SecureString objects, not plain strings."
    }

    if ($imported.ApiKey.Length -eq 0 -or $imported.SharedSecret.Length -eq 0) {
        throw "ACTIVENet credential file contains an empty ApiKey or SharedSecret."
    }

    return [PSCustomObject]@{
        ApiKey       = [System.Security.SecureString]$imported.ApiKey
        SharedSecret = [System.Security.SecureString]$imported.SharedSecret
    }
}

function Get-EntraAuthCertificate {
    <#
    .SYNOPSIS
        Retrieves the X.509 certificate for Entra ID authentication from the Windows Certificate Store.
    .DESCRIPTION
        Looks up a certificate by thumbprint in Cert:\LocalMachine\My (with optional fallback to
        Cert:\CurrentUser\My), verifies that it possesses a usable private key, and confirms it
        is currently within its validity period.
    .PARAMETER Thumbprint
        The SHA-1 thumbprint of the certificate.
    .PARAMETER AllowCurrentUserFallback
        When set, checks Cert:\CurrentUser\My if not found in Cert:\LocalMachine\My.
    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter(Mandatory = $false)]
        [switch]$AllowCurrentUserFallback
    )

    $cleanThumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($cleanThumbprint)) {
        throw "Invalid certificate thumbprint provided."
    }

    $cert = Get-Item -Path "Cert:\LocalMachine\My\$cleanThumbprint" -ErrorAction SilentlyContinue
    if ($null -eq $cert -and $AllowCurrentUserFallback.IsPresent) {
        $cert = Get-Item -Path "Cert:\CurrentUser\My\$cleanThumbprint" -ErrorAction SilentlyContinue
    }

    if ($null -eq $cert) {
        throw "Certificate with thumbprint '$cleanThumbprint' was not found in the certificate store."
    }

    if (-not $cert.HasPrivateKey) {
        throw "Certificate '$cleanThumbprint' does not contain a private key."
    }

    $nowLocal = Get-Date
    if ($nowLocal -lt $cert.NotBefore -or $nowLocal -gt $cert.NotAfter) {
        throw "Certificate '$cleanThumbprint' is expired or not yet valid (Valid: $($cert.NotBefore.ToString('u')) to $($cert.NotAfter.ToString('u')))."
    }

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
}

function New-EntraClientAssertionJwt {
    <#
    .SYNOPSIS
        Builds a signed RFC 7523 JWT client assertion for Microsoft Entra ID OAuth2 token acquisition.
    .DESCRIPTION
        Constructs a JWT header (RS256, x5t thumbprint) and payload (aud, iss, sub, jti, nbf, exp)
        and signs it with the certificate's RSA private key using SHA-256 and PKCS#1 v1.5 padding.
    .PARAMETER TenantId
        The Entra ID directory (tenant) ID.
    .PARAMETER ClientId
        The Entra ID application (client) ID.
    .PARAMETER Certificate
        The X509Certificate2 containing the RSA private key.
    .PARAMETER ReferenceTimeUtc
        Optional UTC timestamp override for deterministic testing.
    .OUTPUTS
        System.String. The signed compact JWS assertion string.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory JWT builder that does not modify system state')]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [DateTimeOffset]$ReferenceTimeUtc = [DateTimeOffset]::UtcNow
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "Cannot sign client assertion: provided certificate does not have a private key."
    }

    $nbf = $ReferenceTimeUtc.ToUnixTimeSeconds()
    $exp = $ReferenceTimeUtc.AddMinutes(10).ToUnixTimeSeconds()
    $jti = [Guid]::NewGuid().ToString()

    $header = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-Base64UrlString -Bytes $Certificate.GetCertHash()
    }

    $payload = [ordered]@{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        exp = $exp
        iss = $ClientId
        jti = $jti
        nbf = $nbf
        sub = $ClientId
    }

    $headerJson = $header | ConvertTo-Json -Compress
    $payloadJson = $payload | ConvertTo-Json -Compress

    $headerEncoded = ConvertTo-Base64UrlString -Bytes ([System.Text.Encoding]::UTF8.GetBytes($headerJson))
    $payloadEncoded = ConvertTo-Base64UrlString -Bytes ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))

    $signingInput = "$headerEncoded.$payloadEncoded"
    $signingBytes = [System.Text.Encoding]::UTF8.GetBytes($signingInput)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) {
        $rsa = [System.Security.Cryptography.RSA]$Certificate.PrivateKey
    }
    if ($null -eq $rsa) {
        throw "Unable to access RSA private key handle on certificate."
    }

    $signatureBytes = $rsa.SignData(
        $signingBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $signatureEncoded = ConvertTo-Base64UrlString -Bytes $signatureBytes

    return "$signingInput.$signatureEncoded"
}

Export-ModuleMember -Function @(
    'ConvertTo-Base64UrlString',
    'ConvertFrom-SecureStringPlain',
    'Get-ActiveNetCredential',
    'Get-EntraAuthCertificate',
    'New-EntraClientAssertionJwt'
)
