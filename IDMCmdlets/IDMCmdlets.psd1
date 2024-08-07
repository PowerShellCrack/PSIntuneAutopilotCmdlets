@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'IDMCmdlets.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.3.5'

    # ID used to uniquely identify this module
    GUID = 'a8428a2b-be4c-43c7-b44c-ea20d0d04490'

    # Author of this module
    Author = 'Powershellcrack'

    # Company or vendor of this module
    #CompanyName = ''

    # Copyright statement for this module
    Copyright = '(c) 2022 Powershellcrack. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'A module designed to help manage devices in Intune'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    #ProcessorArchitecture = 'None'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        'Az.Accounts',
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Applications'
    )

    # Assemblies that must be loaded prior to importing this module
    #RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    #ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    #TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    #FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Add-IDMGraphAppCertAuth'
        'Connect-IDMGraphApp'
        'Get-IDMAppProtectionPolicies'
        'Get-IDMAutopilotDevice'
        'Get-IDMAutopilotProfile'
        'Get-IDMAzureDeviceExtension'
        'Get-IDMAzureDevices'
        'Get-IDMAzureGroup'
        'Get-IDMAzureUser'
        'Get-IDMAzureUsers'
        'Get-IDMCompliancePolicies'
        'Get-IDMCompliancePolicyOSRelease'
        'Get-IDMDevice'
        'Get-IDMDeviceAADUser'
        'Get-IDMDeviceAssignedUser'
        'Get-IDMDeviceCategory'
        'Get-IDMDevicePendingActions'
        'Get-IDMDevices'
        'Get-IDMGraphAppAuthToken'
        'Get-IDMIntuneAssignments'
        'Get-IDMRole'
        'Get-IDMRoleAssignmentGroups'
        'Get-IDMScopeTag'
        'Get-IDMScopeTagAssignment'
        'Get-IDMStaleAzureDevices'
        'Get-IDMStaleDevices'
        'Invoke-IDMDeviceAction'
        'Invoke-IDMGraphBatchRequests'
        'Invoke-IDMGraphRequests'
        'Invoke-IDMRoleAssignment'
        'Invoke-IDMRoleAssignmentAll'
        'Invoke-IDMRoleAssignmentScopeTag'
        'Invoke-IDMScopeTagAssignment'
        'New-IDMAzureDynamicGroup'
        'New-IDMAzureGroup'
        'New-IDMGraphApp'
        'New-IDMGraphAuthCert'
        'New-IDMRole'
        'New-IDMRoleDefinitionBeta'
        'New-IDMScopeTag'
        'Remove-IDMAzureGroup'
        'Remove-IDMDeviceRecords'
        'Remove-IDMRole'
        'Remove-IDMScopeTag'
        'Remove-IDMStaleDevices'
        'Set-IDMAutopilotDeviceTag'
        'Set-IDMAzureDeviceExtension'
        'Set-IDMDeviceAssignedUser'
        'Set-IDMDeviceCategory'
        'Set-IDMResourceFriendlyName'
        'Set-IDMResourceFriendlyType'
        'Set-IDMRole'
        'Split-IDMRequests'
        'Update-IDMAppProtectionPolicyOSCondition'
        'Update-IDMAzureDynamicGroup'
        'Update-IDMCompliancePolicyOSVersion'
        'Update-IDMGraphApp'
        'Update-IDMRoleAssignmentGroups'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    #FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Intune','Devices','MDM','Graph','Autopilot','Azure')

            # A URL to the license for this module.
            LicenseUri = 'https://raw.githubusercontent.com/PowerShellCrack/PSIntuneAutopilotCmdlets/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/PowerShellCrack/PSIntuneAutopilotCmdlets'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'https://github.com/PowerShellCrack/PSIntuneAutopilotCmdlets/blob/main/CHANGELOG.md'

            # External dependent modules of this module
            # ExternalModuleDependencies = ''

        } # End of PSData hashtable

     } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/PowerShellCrack/PSIntuneAutopilotCmdlets/blob/main/README.MD'

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}