#Requires -Version 5.1
BeforeAll {
    $modulePath = Resolve-Path (Join-Path $PSScriptRoot '..\ActiveNetAPI.psd1')
    Import-Module $modulePath -Force
}

Describe 'ActiveNetAPI Module v2.0.0 Manifest & Export Tests' {
    It 'Preserves the exact PowerShell Gallery GUID and exports version 2.0.0' {
        $manifestPath = Resolve-Path (Join-Path $PSScriptRoot '..\ActiveNetAPI.psd1')
        $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        
        $manifest.Guid.ToString() | Should -Be 'ebe28e05-8dc6-4175-86d0-97b761d4bdb0'
        $manifest.Version.ToString() | Should -Be '2.0.0'
        $manifest.Author | Should -Be 'Justin Romanello'
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'Exports the expected functions and aliases' {
        $mod = Get-Module -Name 'ActiveNetAPI'
        $mod.ExportedFunctions.Keys | Should -Contain 'Invoke-ActiveNetAPI'
        $mod.ExportedFunctions.Keys | Should -Contain 'New-DynamicDigitalSignature'
        $mod.ExportedAliases.Keys | Should -Contain 'Invoke-ANAPI'
        $mod.ExportedAliases.Keys | Should -Contain 'New-ANDigitalSignature'
    }
}

Describe 'New-DynamicDigitalSignature Cryptographic & Parameter Tests' {
    It 'Generates identical deterministic 64-character lowercase SHA-256 signatures for plaintext and SecureString' {
        $plainKey = 'SampleApiKey123'
        $plainSecret = 'SampleSharedSecret456'
        $epoch = 1700000000

        $secKey = ConvertTo-SecureString $plainKey -AsPlainText -Force
        $secSecret = ConvertTo-SecureString $plainSecret -AsPlainText -Force

        $sigPlain = New-DynamicDigitalSignature -ApiKey $plainKey -Secret $plainSecret -EpochSeconds $epoch
        $sigSecure = New-DynamicDigitalSignature -ApiKey $secKey -Secret $secSecret -EpochSeconds $epoch

        $sigPlain.Length | Should -Be 64
        $sigPlain | Should -Match '^[0-9a-f]{64}$'
        $sigSecure | Should -Be $sigPlain
    }

    It 'Accepts legacy parameter names (-API_Key and -SharedSecretKey)' {
        $sig = New-DynamicDigitalSignature -API_Key 'SampleKey' -SharedSecretKey 'SampleSecret' -EpochSeconds 1700000000
        $sig.Length | Should -Be 64
        $sig | Should -Match '^[0-9a-f]{64}$'
    }

    It 'Works via exported alias New-ANDigitalSignature' {
        $sig = New-ANDigitalSignature -ApiKey 'SampleKey' -Secret 'SampleSecret' -EpochSeconds 1700000000
        $sig.Length | Should -Be 64
    }

    It 'Throws a descriptive error when non-string and non-SecureString is provided' {
        { New-DynamicDigitalSignature -ApiKey 12345 -Secret 'SampleSecret' } | Should -Throw
    }
}

Describe 'Invoke-ActiveNetAPI Request & Logic Tests' {
    It 'Throws an error if neither Signature nor Secret is provided' {
        { Invoke-ActiveNetAPI -OrgId 'testorg' -ResourceName 'activities' -ApiKey 'testkey' } |
            Should -Throw '*Either -Signature or -Secret must be provided*'
    }

    It 'Constructs valid URIs and handles Mocked successful responses' {
        $script:capturedUri = $null
        Mock -ModuleName ActiveNetAPI Invoke-RestMethod {
            $script:capturedUri = $Uri
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{
                    response_code = '0000'
                    response_message = 'Success'
                    page_info = [PSCustomObject]@{
                        page_number = 1
                        total_page = 1
                    }
                }
                body = @(
                    [PSCustomObject]@{ id = 1; name = 'Basketball' }
                )
            }
        }

        $res = Invoke-ActiveNetAPI -OrgId 'sampleOrg' -ResourceName 'activities' -ApiKey 'testKey' -Secret 'testSecret' -RequestParameters @{ status = 'active' }
        $res.headers.response_code | Should -Be '0000'
        $res.body[0].name | Should -Be 'Basketball'
        $script:capturedUri | Should -Match 'api\.amp\.active\.com/anet-systemapi-sec/sampleOrg/api/v1/activities\?status=active&api_key=testKey&sig=[0-9a-f]{64}'
    }

    It 'Switches service gateway to anet-systemapi-ca-sec when -Canada is passed' {
        $script:capturedUri = $null
        Mock -ModuleName ActiveNetAPI Invoke-RestMethod {
            $script:capturedUri = $Uri
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{ response_code = '0000'; response_message = 'Success' }
                body = @([PSCustomObject]@{ id = 2; name = 'Hockey' })
            }
        }

        $res = Invoke-ActiveNetAPI -OrgId 'caOrg' -ResourceName 'activities' -ApiKey 'testKey' -Secret 'testSecret' -Canada
        $res.body[0].name | Should -Be 'Hockey'
        $script:capturedUri | Should -Match 'anet-systemapi-ca-sec/caOrg/api/v1/activities'
    }

    It 'Paginates through multiple pages when -AllPages is specified' {
        $script:callCount = 0
        Mock -ModuleName ActiveNetAPI Invoke-RestMethod {
            $script:callCount++
            if ($Headers.page_info -match '"page_number":1') {
                return [PSCustomObject]@{
                    headers = [PSCustomObject]@{
                        response_code = '0000'
                        page_info = [PSCustomObject]@{ page_number = 1; total_page = 2 }
                    }
                    body = @([PSCustomObject]@{ id = 101 })
                }
            } else {
                return [PSCustomObject]@{
                    headers = [PSCustomObject]@{
                        response_code = '0000'
                        page_info = [PSCustomObject]@{ page_number = 2; total_page = 2 }
                    }
                    body = @([PSCustomObject]@{ id = 102 })
                }
            }
        }

        $allRes = Invoke-ActiveNetAPI -OrgId 'pagedOrg' -ResourceName 'facilities' -ApiKey 'testKey' -Secret 'testSecret' -AllPages
        $allRes.body.Count | Should -Be 2
        $allRes.body[0].id | Should -Be 101
        $allRes.body[1].id | Should -Be 102
        $script:callCount | Should -Be 2
    }

    It 'Retries on transient HTTP 429 and succeeds on subsequent attempt' {
        $script:attempts = 0
        Mock -ModuleName ActiveNetAPI Invoke-RestMethod {
            $script:attempts++
            if ($script:attempts -eq 1) {
                $customEx = [System.Exception]::new('Over QPS: 429')
                $webResp = [PSCustomObject]@{ StatusCode = 429 }
                $errRec = [System.Management.Automation.ErrorRecord]::new(
                    $customEx,
                    'RateLimit429',
                    [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
                    $null
                )
                Add-Member -InputObject $customEx -MemberType NoteProperty -Name 'Response' -Value $webResp
                throw $errRec
            }
            return [PSCustomObject]@{
                headers = [PSCustomObject]@{ response_code = '0000'; response_message = 'Success' }
                body = @([PSCustomObject]@{ id = 999 })
            }
        }

        $retryRes = Invoke-ActiveNetAPI -OrgId 'retryOrg' -ResourceName 'activities' -ApiKey 'testKey' -Secret 'testSecret' -MaxRetries 2 -BaseBackoffMs 10
        $retryRes.body[0].id | Should -Be 999
        $script:attempts | Should -Be 2
    }
}
