<#
.SYNOPSIS
    Invokes the ACTIVENet REST API for a specified resource with retry, pagination, and credential hardening.
.DESCRIPTION
    Constructs and executes authenticated REST calls against the ACTIVENet API Gateway.
    
    Enterprise modernization features (v2.0.0):
    - Accepts credentials as [System.Security.SecureString] or [string] with unmanaged BSTR zero-freeing.
    - Automatic dynamic signature calculation when -Secret is provided (no manual signature step required).
    - Robust transient HTTP retry with exponential backoff on HTTP 429 (Rate Limit / Over QPS) and 5xx errors.
    - Automated result pagination across all pages using the -AllPages switch.
    - Dual gateway routing: defaults to US Gateway (api.amp.active.com), supports Canada via -Canada (anet-systemapi-ca-sec).
    - Full backward compatibility with v1 parameter names and aliases.
.PARAMETER OrgId
    The ACTIVENet organization ID (e.g. 'your-org-id' or trainer site ID). This parameter is required.
.PARAMETER ResourceName
    The name or relative path of the API resource (e.g., 'activities', 'facilityschedules', 'facilities').
.PARAMETER RequestParameters
    A hashtable of key-value query parameters to include in the request.
.PARAMETER ApiKey
    Your ACTIVENet API key as [System.Security.SecureString] or [string].
.PARAMETER Signature
    Pre-computed SHA-256 dynamic digital signature string. If omitted, -Secret must be provided.
.PARAMETER Secret
    Your ACTIVENet shared secret key as [System.Security.SecureString] or [string]. When provided,
    Invoke-ActiveNetAPI dynamically generates and updates signatures across all paginated requests.
.PARAMETER Canada
    Switch indicating whether to route to the Canadian ACTIVENet gateway service (anet-systemapi-ca-sec).
.PARAMETER PageNumber
    The initial or specific page number to retrieve. Defaults to '1'.
.PARAMETER AllPages
    Switch indicating whether to automatically paginate through all available result pages and aggregate records.
.PARAMETER PageSize
    Number of records to request per page (1 to 500). Defaults to 250.
.PARAMETER MaxRetries
    Maximum number of retry attempts on transient network or HTTP 429/5xx errors. Defaults to 3.
.PARAMETER BaseBackoffMs
    Base backoff delay in milliseconds for exponential retry. Defaults to 1500.
.PARAMETER BaseUri
    Base URI for the ACTIVENet Gateway. Defaults to 'https://api.amp.active.com'.
.OUTPUTS
    Returns the parsed API response object, or an aggregated response with combined records when -AllPages is specified.
.EXAMPLE
    PS> # Dynamic signature generation with SecureString credentials and full pagination:
    PS> $res = Invoke-ActiveNetAPI -OrgId 'myorg' -ResourceName 'activities' -ApiKey $secKey -Secret $secSecret -AllPages
.EXAMPLE
    PS> # Backward-compatible v1 calling syntax:
    PS> $sig = New-DynamicDigitalSignature -ApiKey $key -Secret $secret
    PS> $res = Invoke-ActiveNetAPI -orgId 'myorg' -resourceName 'activities' -apiKey $key -signature $sig
#>
function Invoke-ActiveNetAPI {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('organizationId')]
        [string]$OrgId,

        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('endpoint', 'resource')]
        [string]$ResourceName,

        [Parameter(Mandatory = $false, Position = 2)]
        [Alias('parameters', 'queryParameters')]
        [hashtable]$RequestParameters = @{},

        [Parameter(Mandatory = $true, Position = 3)]
        [Alias('API_Key', 'Key')]
        [object]$ApiKey,

        [Parameter(Mandatory = $false, Position = 4)]
        [Alias('sig')]
        [string]$Signature,

        [Parameter(Mandatory = $false)]
        [Alias('sharedSecret', 'sharedSecretKey', 'Shared_Secret')]
        [object]$Secret,

        [Parameter(Mandatory = $false)]
        [Alias('IsCanada')]
        [switch]$Canada,

        [Parameter(Mandatory = $false)]
        [Alias('page')]
        [string]$PageNumber = '1',

        [Parameter(Mandatory = $false)]
        [Alias('all')]
        [switch]$AllPages,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 500)]
        [int]$PageSize = 250,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 60000)]
        [int]$BaseBackoffMs = 1500,

        [Parameter(Mandatory = $false)]
        [Alias('baseUrl')]
        [string]$BaseUri = 'https://api.amp.active.com'
    )

    if ([string]::IsNullOrWhiteSpace($Signature) -and $null -eq $Secret) {
        throw "Either -Signature or -Secret must be provided for authentication."
    }

    # Internal helper for string extraction from SecureString or string
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

    $plainApiKey = & $extractString $ApiKey 'ApiKey'

    # Determine service gateway and base URI
    $trimmedBase = $BaseUri.TrimEnd('/')
    $trimmedResource = $ResourceName.TrimStart('/')

    $serviceName = if ($Canada.IsPresent) {
        'anet-systemapi-ca-sec'
    } else {
        'anet-systemapi-sec'
    }

    # Format query parameters
    $queryPairs = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $RequestParameters -and $RequestParameters.Count -gt 0) {
        foreach ($key in ($RequestParameters.Keys | Sort-Object)) {
            $val = [string]$RequestParameters[$key]
            $encodedKey = [System.Uri]::EscapeDataString([string]$key)
            $encodedVal = [System.Uri]::EscapeDataString($val)
            $queryPairs.Add("$encodedKey=$encodedVal")
        }
    }
    $queryPrefix = if ($queryPairs.Count -gt 0) { ($queryPairs -join '&') + '&' } else { '' }

    $allRecords = [System.Collections.Generic.List[object]]::new()
    $currentPage = [int]$PageNumber
    if ($currentPage -lt 1) { $currentPage = 1 }
    $lastResponse = $null
    $hasMorePages = $true

    while ($hasMorePages) {
        # Prepare page_info header
        $pageInfoJson = ([ordered]@{
            page_number            = $currentPage
            total_records_per_page = $PageSize
        } | ConvertTo-Json -Compress)

        $headers = @{
            'Accept'       = 'application/json'
            'content-type' = 'application/json'
            'page_info'    = $pageInfoJson
        }

        # Calculate dynamic signature if Secret was provided, else use supplied Signature
        $currentSig = if ($null -ne $Secret) {
            if (Get-Command -Name 'New-DynamicDigitalSignature' -ErrorAction SilentlyContinue) {
                New-DynamicDigitalSignature -ApiKey $ApiKey -Secret $Secret
            } else {
                # Fallback implementation if function not in scope
                $plainSecret = & $extractString $Secret 'Secret'
                $nowSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $payload = "$plainApiKey$plainSecret$nowSeconds"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
                } finally {
                    $sha.Dispose()
                }
            }
        } else {
            $Signature
        }

        $uri = "$trimmedBase/$serviceName/$OrgId/api/v1/$trimmedResource`?$queryPrefix" + "api_key=$plainApiKey&sig=$currentSig"

        # HTTP request execution with exponential backoff retry on 429 and 5xx
        $attempt = 0
        $requestSucceeded = $false
        $pageResponse = $null

        while ($attempt -le $MaxRetries) {
            $attempt++
            try {
                $pageResponse = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
                $requestSucceeded = $true
                break
            } catch {
                $statusCode = 0
                if ($null -ne $_.Exception -and $null -ne $_.Exception.PSObject.Properties['Response'] -and $null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                $errText = $_.ToString()
                if ($null -ne $_.Exception -and $null -ne $_.Exception.Message) { $errText += " " + $_.Exception.Message }
                $isQps = ($statusCode -eq 429) -or ($statusCode -eq 403 -and $errText -match '(?i)over\s*qps')
                $isRetryable = ($statusCode -eq 0) -or ($statusCode -ge 500 -and $statusCode -lt 600) -or $isQps

                if ($isRetryable -and $attempt -le $MaxRetries) {
                    $delayMs = [int]($BaseBackoffMs * [Math]::Pow(2, ($attempt - 1)))
                    Write-Verbose "Transient error (Status: $statusCode). Retrying attempt $attempt of $MaxRetries in ${delayMs}ms..."
                    if ($delayMs -gt 0) {
                        Start-Sleep -Milliseconds $delayMs
                    }
                    continue
                }

                throw "Failed to invoke ACTIVENet API on page $currentPage (Status: $statusCode): $($_.Exception.Message)"
            }
        }

        if (-not $requestSucceeded -or $null -eq $pageResponse) {
            throw "Failed to retrieve response from ACTIVENet API for resource '$ResourceName'."
        }

        $lastResponse = $pageResponse

        # If not paginating, return immediately
        if (-not $AllPages.IsPresent) {
            return $pageResponse
        }

        # Handle ACTIVENet specific response headers
        if ($null -ne $pageResponse.PSObject.Properties['headers'] -and $null -ne $pageResponse.headers) {
            $respCode = [string]$pageResponse.headers.response_code
            if ($respCode -eq '0001') {
                # Documented empty result set
                break
            }
            if ($respCode -ne '0000') {
                $respMsg = if ($null -ne $pageResponse.headers.PSObject.Properties['response_message']) {
                    [string]$pageResponse.headers.response_message
                } else {
                    "API code $respCode"
                }
                throw "ACTIVENet returned error code '$respCode': $respMsg"
            }
        }

        # Collect records from body
        if ($null -ne $pageResponse.PSObject.Properties['body'] -and $null -ne $pageResponse.body) {
            $bodyItems = @($pageResponse.body)
            foreach ($item in $bodyItems) {
                if ($null -ne $item) {
                    $allRecords.Add($item)
                }
            }

            # Check total_page in page_info if provided
            $totalPages = $null
            if ($null -ne $pageResponse.headers -and
                $null -ne $pageResponse.headers.PSObject.Properties['page_info'] -and
                $null -ne $pageResponse.headers.page_info -and
                $null -ne $pageResponse.headers.page_info.PSObject.Properties['total_page']) {
                $totalPages = [int]$pageResponse.headers.page_info.total_page
            }

            if ($null -ne $totalPages -and $totalPages -gt 0) {
                if ($currentPage -ge $totalPages) {
                    $hasMorePages = $false
                } else {
                    $currentPage++
                }
            } else {
                if ($bodyItems.Count -lt $PageSize) {
                    $hasMorePages = $false
                } else {
                    $currentPage++
                }
            }
        } else {
            $hasMorePages = $false
        }
    }

    # Return aggregated PSCustomObject maintaining response contract
    return [PSCustomObject]@{
        headers = if ($null -ne $lastResponse -and $null -ne $lastResponse.PSObject.Properties['headers']) {
            $lastResponse.headers
        } else {
            [PSCustomObject]@{
                response_code = '0000'
                response_message = 'Success'
            }
        }
        body    = $allRecords.ToArray()
    }
}
