#   #   #   GetFlexRegPrograms  #   #   #
#   Required function: New-DynamicDigitalSignature and Invoke-ActiveNetAPI
#   Variables
$apiKey = 'your_api_key'
$sharedSecretKey = 'your_shared_secret_key'
$resourceName = 'flexregprograms'
$requestParameters = @{}

#   Optional vars
$requestParameters['program_status'] = 'Open'

#   Call API
$response = Invoke-ActiveNetAPI `
    -orgId $orgId `
    -resourceName $resourceName `
    -requestParameters $requestParameters `
    -apiKey $apiKey `
    -signature (New-DynamicDigitalSignature -ApiKey $apiKey -SharedSecretKey $sharedSecretKey)

$flexRegPrograms = $response.body

#   Determine if there are more than 500 results
if ($flexRegPrograms.count -eq 500) {
    #   Add programs to a hashset
    $flexRegProgramsHashset = [Collections.Generic.Hashset[PSCustomObject]]@()
    foreach ($program in $flexRegPrograms) {
        [void]$flexRegProgramsHashset.Add($program)
    }

    #   Loop through the pages
    $n = 2
    while ($flexRegPrograms.count -eq 500) {
        $response = Invoke-ActiveNetAPI `
            -orgId $orgId `
            -resourceName $resourceName `
            -requestParameters $requestParameters `
            -apiKey $apiKey `
            -signature (New-DynamicDigitalSignature -ApiKey $apiKey -SharedSecretKey $sharedSecretKey) `
            -pageNumber $n

        $flexRegPrograms = $response.body

        #   Add programs to the hashset
        foreach ($program in $flexRegPrograms) {
            [void]$flexRegProgramsHashset.Add($program)
        }
        $n++
        Start-Sleep -Seconds 1
    }
}

return $flexRegProgramsHashset