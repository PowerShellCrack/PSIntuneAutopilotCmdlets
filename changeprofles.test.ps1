$DeviceforProfiles = @(
    'DTOLAB-PC',
    'DTOLAB-PC2'
)

#user id
$AssignedUser = "tracyr@dtolab.ltd" 

#MAIN
#==============================================

Install-Module Az.Accounts
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Applications
Install-Module IDMCmdlets

$Global:GraphEndpoint = 'https://graph.microsoft.com'
Connect-MgGraph

$AllDevices = Get-IDMDevices

#change assigned profile for eahc device in list
foreach ($Device in $DeviceforProfiles)
{
    $DeviceID = $AllDevices | Where-Object { $_.DisplayName -eq $Device } | Select-Object -ExpandProperty Id
    Set-IDMDeviceAssignedUser -DeviceId $DeviceID -AssignedUser $AssignedUser
}