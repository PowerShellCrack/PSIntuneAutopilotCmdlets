# Load cmdlets from module subfolder
$script:GraphScopes = @(
    'Agreement.Read.All'
    'Directory.AccessAsUser.All'
    'Directory.Read.All'
    'RoleManagement.Read.Directory'
    'Policy.Read.All'
    'Organization.Read.All'
    'User.ReadBasic.All'
    'Group.Read.All'
    'GroupMember.Read.All'
    'Device.Read.All'
    'DeviceManagementApps.Read.All'
    'DeviceManagementApps.ReadWrite.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementConfiguration.ReadWrite.All'
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementManagedDevices.ReadWrite.All'
    'DeviceManagementRBAC.Read.All'
    'DeviceManagementRBAC.ReadWrite.All'
    'DeviceManagementServiceConfig.Read.All'
    'DeviceManagementServiceConfig.ReadWrite.All'
)

$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Path

Resolve-Path "$ModuleRoot\Cmdlets\*.ps1" | ForEach-Object -Process {
. $_.ProviderPath
}
