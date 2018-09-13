#
# Module manifest for module 'AzureRM.DataLakeStore'
#
# Generated by: Microsoft Corporation
#
# Generated on: 3/13/2018
#

@{

# Script module or binary module file associated with this manifest.
# RootModule = ''

# Version number of this module.
ModuleVersion = '0.2.0'

# Supported PSEditions
CompatiblePSEditions = 'Core', 'Desktop'

# ID used to uniquely identify this module
GUID = '3fabfb08-d284-44b8-a982-eaada389075e'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = 'Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Microsoft Azure PowerShell - Azure Data Lake Store cmdlets in PowerShell and PowerShell Core'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.7.2'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @(@{ModuleName = 'Az.Profile'; ModuleVersion = '0.2.0'; })

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = '.\Microsoft.Azure.Management.DataLake.Store.dll', 
    '.\Microsoft.Azure.DataLake.Store.dll', '.\NLog.dll'

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = '.\Microsoft.Azure.Commands.DataLakeStoreFileSystem.format.ps1xml'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('.\Microsoft.Azure.Commands.DataLakeStore.dll')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = 'Get-AzDataLakeStoreTrustedIdProvider', 
    'Remove-AzDataLakeStoreTrustedIdProvider', 
    'Remove-AzDataLakeStoreFirewallRule', 
    'Set-AzDataLakeStoreTrustedIdProvider', 
    'Add-AzDataLakeStoreTrustedIdProvider', 
    'Get-AzDataLakeStoreFirewallRule', 
    'Set-AzDataLakeStoreFirewallRule', 
    'Add-AzDataLakeStoreFirewallRule', 
    'Add-AzDataLakeStoreItemContent', 
    'Enable-AzDataLakeStoreKeyVault', 
    'Export-AzDataLakeStoreItem', 
    'Get-AzDataLakeStoreChildItem', 'Get-AzDataLakeStoreItem', 
    'Get-AzDataLakeStoreItemAclEntry', 
    'Get-AzDataLakeStoreItemContent', 
    'Get-AzDataLakeStoreItemOwner', 
    'Get-AzDataLakeStoreItemPermission', 
    'Import-AzDataLakeStoreItem', 'Get-AzDataLakeStoreAccount', 
    'Join-AzDataLakeStoreItem', 'Move-AzDataLakeStoreItem', 
    'New-AzDataLakeStoreAccount', 'New-AzDataLakeStoreItem', 
    'Remove-AzDataLakeStoreAccount', 
    'Remove-AzDataLakeStoreItem', 
    'Remove-AzDataLakeStoreItemAcl', 
    'Remove-AzDataLakeStoreItemAclEntry', 
    'Set-AzDataLakeStoreItemAclEntry', 
    'Set-AzDataLakeStoreAccount', 'Set-AzDataLakeStoreItemAcl', 
    'Set-AzDataLakeStoreItemExpiry', 
    'Set-AzDataLakeStoreItemOwner', 
    'Set-AzDataLakeStoreItemPermission', 
    'Test-AzDataLakeStoreAccount', 'Test-AzDataLakeStoreItem', 
    'Export-AzDataLakeStoreChildItemProperties', 
    'Get-AzDataLakeStoreChildItemSummary'

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = 'Get-AdlStoreTrustedIdProvider', 'Remove-AdlStoreTrustedIdProvider', 
    'Remove-AdlStoreFirewallRule', 'Set-AdlStoreTrustedIdProvider', 
    'Add-AdlStoreTrustedIdProvider', 'Get-AdlStoreFirewallRule', 
    'Set-AdlStoreFirewallRule', 'Add-AdlStoreFirewallRule', 
    'Add-AdlStoreItemContent', 'Export-AdlStoreItem', 
    'Enable-AdlStoreKeyVault', 'Get-AdlStoreChildItem', 
    'Get-AdlStoreItem', 'Get-AdlStoreItemAclEntry', 
    'Get-AdlStoreItemContent', 'Get-AdlStoreItemOwner', 
    'Get-AdlStoreItemPermission', 'Import-AdlStoreItem', 'Get-AdlStore', 
    'Join-AdlStoreItem', 'Move-AdlStoreItem', 'New-AdlStore', 
    'New-AdlStoreItem', 'Remove-AdlStore', 'Remove-AdlStoreItem', 
    'Remove-AdlStoreItemAcl', 'Remove-AdlStoreItemAclEntry', 
    'Set-AdlStoreItemAclEntry', 'Set-AdlStore', 'Set-AdlStoreItemAcl', 
    'Set-AdlStoreItemExpiry', 'Set-AdlStoreItemOwner', 
    'Set-AdlStoreItemPermission', 'Test-AdlStore', 'Test-AdlStoreItem', 
    'Get-AdlStoreChildItemSummary', 'Export-AdlStoreChildItemProperties'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'Azure', 'ResourceManager', 'ARM', 'DataLake', 'Store'

        # A URL to the license for this module.
        LicenseUri = 'https://aka.ms/azps-license'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Azure/azure-powershell'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'Initial Release with PowerShell and PowerShell Core Support'

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

