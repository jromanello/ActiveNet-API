@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'ActiveNetAPI.psm1'

    # Version number of this module.
    ModuleVersion = '2.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'ebe28e05-8dc6-4175-86d0-97b761d4bdb0'

    # Author of this module
    Author = 'Justin Romanello'

    # Company or vendor of this module
    CompanyName = 'Justin Romanello'

    # Copyright statement for this module
    Copyright = '(c) Justin Romanello. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Enterprise PowerShell module for ACTIVENet REST API integration, dynamic SHA-256 digital signature calculation with SecureString zero-free unmanaged memory semantics, and automatic retry/pagination.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Invoke-ActiveNetAPI',
        'New-DynamicDigitalSignature'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @(
        'Invoke-ANAPI',
        'New-ANDigitalSignature'
    )

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveNet', 'API', 'REST', 'Recreation', 'Parks', 'Scheduling', 'SecureString', 'SHA256')
            LicenseUri = 'https://github.com/jromanello/ActiveNet-API/blob/main/LICENSE'
            ProjectUri = 'https://github.com/jromanello/ActiveNet-API'
            ReleaseNotes = 'v2.0.0: Enterprise modernization with SecureString credentials, zero-free unmanaged memory semantics, modern SHA256 hashing, automatic retry with exponential backoff on HTTP 429/5xx, auto-pagination (-AllPages), and dual PowerShell 5.1 / 7+ compatibility.'
        }
    }
}
