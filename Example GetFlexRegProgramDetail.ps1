#   #   #   GetFlexRegProgramDetail  #   #   #
#   Required function: New-DynamicDigitalSignature and Invoke-ActiveNetAPI
#   Variables
$apiKey = 'your_api_key'
$sharedSecretKey = 'your_shared_secret_key'
$programId = '899'
$resourceName = "flexregprograms/$programId"
$requestParameters = @{}

#   Call API
$response = Invoke-ActiveNetAPI `
    -orgId $orgId `
    -resourceName $resourceName `
    -requestParameters $requestParameters `
    -apiKey $apiKey `
    -signature (New-DynamicDigitalSignature -ApiKey $apiKey -SharedSecretKey $sharedSecretKey)

$flexRegProgramDetail = $response.body

return $flexRegProgramDetail