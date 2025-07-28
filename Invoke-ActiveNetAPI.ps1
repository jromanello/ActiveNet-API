function Invoke-ActiveNetAPI {
    <#
    .SYNOPSIS
        Invokes the ActiveNet API for the specified resource. 
    .DESCRIPTION
        This function constructs the API request URL (URI) by using the provided organization ID, resource name, request parameters, and digital signature. It then invokes the ActiveNet API and returns the response.
    .PARAMETER orgId
        The organization ID for the API request. This parameter is required. Use either the live site or trainer site.
    .PARAMETER resourceName
        The name of the resource to access in the API. This parameter is required. List of resources found here: found here: https://help.aw.active.com/ActiveNet/standard/en_US/Api_list.htm
    .PARAMETER requestParameters
        A hashtable of optional key:value pairs to include in the API request. This parameter is optional.
    .PARAMETER apiKey
        Your API key. This parameter is required.
    .PARAMETER signature
        A SHA-256 hash based digital signature that should be a concatenation of the API key, shared secret key, and current timestamp (in epoch seconds). This parameter is required.
    .PARAMETER canada
        A switch to indicate if the Canadian service name should be used. This parameter is optional.
    .PARAMETER pagenumber
        The page number for paginated results. Defaults to '1'. This parameter is optional. Used for looping through response results.
    .OUTPUTS
        Returns the response from the ActiveNet API as a PowerShell object.        
    .EXAMPLE
        PS> $response = Invoke-ActiveNetAPI -orgId 'your org ID' -resourceName 'activities' -requestParameters @{activity_status_id = '1'; site_ids = '101,102'} -apiKey 'your_api_key' -signature 'your_digital_signature'
    .EXAMPLE
        PS> $response = Invoke-ActiveNetAPI -orgId $trainerSite -resourceName $resource -requestParameters $parameters -apiKey $key -signature (New-DynamicDigitalSignature)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$orgId,

        [Parameter(Mandatory = $true)]
        [string]$resourceName,

        [Parameter()]
        [hashtable]$requestParameters = @{},

        [Parameter(Mandatory = $true)]
        [string]$apiKey,

        [Parameter(Mandatory = $true)]
        [string]$signature,

        [switch]$canada = $false,

        [string]$pageNumber = '1'
    )

    #   Create headers
    $perPage = '500'
    $pageInfo = @{
        "page_number" = $pageNumber
        "total_records_per_page" = $perPage
    } | ConvertTo-Json -Compress
    $headers = @{
        "accept" = "application/json"
        "content-type" = "application/json"
        "page_info" = $pageInfo
    }

    #   Create URI
    #   Format: https://api.amp.active.com/{service name}/{org id}/api/v1/{resource name}?{optional parameters 1}&{optional parameters 2}&api_key={your API key}&sig={dynamic digital signature}
    $serviceName = if ($canada) {
            'anet-systemapi-ca-sec'
        } else {
            'anet-systemapi-sec'
        }
    $urlParameters = if ($requestParameters.Count -gt 0) {
        (($requestparameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&') + '&'
    }
    $uri = 'https://api.amp.active.com/' + $serviceName + '/' + $orgId + '/api/v1/' + $resourceName + '?' + $urlParameters + 'api_key=' + $apiKey + '&sig=' + $signature

    #   Invoke API
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers
        return $response
    } catch {
        Write-Error "Failed to invoke ActiveNet API: $_"
    }
}