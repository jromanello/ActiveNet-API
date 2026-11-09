# ActiveNetAPI PowerShell Module v2.0.0

A high-performance, enterprise-hardened PowerShell module and standalone script suite for authenticating and interacting with the ACTIVENet REST API Gateway.

## Module Details
- **Module Name:** `ActiveNetAPI`
- **Version:** `2.0.0`
- **Author:** Justin Romanello
- **PowerShell Gallery GUID:** `ebe28e05-8dc6-4175-86d0-97b761d4bdb0`
- **Supported Editions:** Windows PowerShell 5.1 (Desktop) and PowerShell Core 7.x+ (Core)

---

## What's New in v2.0.0
- **Dual Credential Ingestion**: Accepts credentials as either `[System.Security.SecureString]` or standard `[string]`.
- **Memory Safety & Zero-Freeing**: Automatically zero-frees unmanaged BSTR memory using `[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR` inside guaranteed `try/finally` blocks when handling SecureStrings.
- **Modern Cryptography**: Deprecates `SHA256Managed` in favor of standard `[System.Security.Cryptography.SHA256]::Create()`.
- **Automatic Dynamic Signatures**: When passing `-Secret`, `Invoke-ActiveNetAPI` automatically generates and refreshes SHA-256 signatures per page request, eliminating manual signature coordination.
- **Resilient Request Execution**: Automatic exponential backoff with jitter on HTTP 429 (Rate Limit / Over QPS) and HTTP 5xx errors.
- **Auto-Pagination**: Seamlessly retrieves all records across multiple pages using the `-AllPages` switch.
- **Gateway Agility**: Defaults to US Gateway (`api.amp.active.com` / `anet-systemapi-sec`), with one-flag switching to Canada via `-Canada` (`anet-systemapi-ca-sec`) and custom `-BaseUri` overrides.
- **Backwards Compatibility**: 100% backward-compatible with v1.x parameters and aliases (`-API_Key`, `-SharedSecretKey`, `-Shared_Secret`, `-orgId`, `-apiKey`, `-signature`).

---

## Exported Cmdlets & Aliases

| Cmdlet / Function | Alias | Purpose |
| :--- | :--- | :--- |
| `New-DynamicDigitalSignature` | `New-ANDigitalSignature` | Computes 64-char lowercase SHA-256 dynamic digital signature from ApiKey + SharedSecret + EpochSeconds |
| `Invoke-ActiveNetAPI` | `Invoke-ANAPI` | Executes authenticated REST calls against ACTIVENet with retry, pagination, and credential hardening |

---

## Installation & Import

### Importing the Module
```powershell
Import-Module "C:\path\to\ActiveNet-API\API\ActiveNetAPI.psd1" -Force
```

### Standalone Script Usage
If you prefer not to import the full module, standalone copies of `Invoke-ActiveNetAPI.ps1` and `New-DynamicDigitalSignature.ps1` are provided directly in this directory:
```powershell
. .\New-DynamicDigitalSignature.ps1
. .\Invoke-ActiveNetAPI.ps1
```

---

## Usage Examples

### 1. Generating a Dynamic Signature with SecureString
```powershell
$secKey = ConvertTo-SecureString "YourApiKey" -AsPlainText -Force
$secSecret = ConvertTo-SecureString "YourSharedSecret" -AsPlainText -Force

# Generates 64-character lowercase SHA-256 signature
$sig = New-DynamicDigitalSignature -ApiKey $secKey -Secret $secSecret
```

### 2. Invoking an Endpoint with Automatic Pagination & Secret
```powershell
$response = Invoke-ActiveNetAPI `
    -OrgId 'your_org_id' `
    -ResourceName 'activities' `
    -RequestParameters @{ activity_status_id = '1' } `
    -ApiKey $secKey `
    -Secret $secSecret `
    -AllPages
```

### 3. Querying Canada Gateway
```powershell
$response = Invoke-ActiveNetAPI `
    -OrgId 'your_ca_org_id' `
    -ResourceName 'facilityschedules' `
    -ApiKey $secKey `
    -Secret $secSecret `
    -Canada
```

### 4. Legacy Backward Compatibility (v1 Calling Syntax)
```powershell
$sig = New-DynamicDigitalSignature -API_Key 'your_api_key' -SharedSecretKey 'your_secret'
$response = Invoke-ActiveNetAPI -orgId 'your_org_id' -resourceName 'activities' -apiKey 'your_api_key' -signature $sig
```
