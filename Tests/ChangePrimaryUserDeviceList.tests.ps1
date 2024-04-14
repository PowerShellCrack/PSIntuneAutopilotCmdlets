$DeviceUpdateList = @(
    'DTOLAB-WKHV001',
    'DTOLAB-WKHV002'
)

#user id
$AssignedUser = "tracyr@dtolab.ltd" 

# Set to $True to update the profile, $False to just see what would happen
$DoProfileUpdate = $False
#MAIN
#==============================================

Install-Module Az.Accounts
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Applications
Install-Module IDMCmdlets -MinimumVersion 1.0.2.2 -Force

$Global:GraphEndpoint = 'https://graph.microsoft.com'
Connect-MgGraph -NoWelcome

$AllDevices = Get-IDMDevices -Platform Windows -Verbose

#assigned profile for each device in list
Write-Host "Found $($AllDevices.Count) devices in Intune." -ForegroundColor Cyan

#loop through each device in the list
#TEST $DeviceName = $DeviceUpdateList[0]
foreach ($DeviceName in $DeviceUpdateList)
{
    Write-Host ("Detecting Assigned user for device {0}..." -f $DeviceName) -NoNewline
    $DeviceID = $AllDevices | Where-Object { $_.deviceName -eq $DeviceName } | Select-Object -ExpandProperty Id
    
    If($null -eq $DeviceID)
    {
        Write-Host "Device not found" -foregroundcolor Yellow
        Continue
    }
    $DeviceAssignedUser = Get-IDMDeviceAssignedUser -DeviceId $DeviceID -Passthru
    
    If($null -eq $DeviceAssignedUser)
    {
        Write-Host "no assigned user found" -foregroundcolor Yellow
    }Elseif($DeviceAssignedUser.UserPrincipalName -eq $AssignedUser){
        Write-Host "assigned user is already correct" -foregroundcolor Green
        Continue
    }Else{
        Write-Host "assigned User: $($DeviceAssignedUser.UserPrincipalName)"
    }
    
    If($DoProfileUpdate)
    {
        Write-Host ("|--Updating Assigned user to: {0}..." -f $DeviceName,$AssignedUser) -NoNewline
        Try{
            #$UpdatedUser = Get-IDMAzureUser -UPN $AssignedUser
            Set-IDMDeviceAssignedUser -DeviceId $DeviceID -UPN $AssignedUser 
            Write-Host "Success" -foregroundcolor Green
        }Catch{
            Write-Host ("Error updating UPN for device {0}: {1}" -f $DeviceName,$_.Exception.message) -ForegroundColor Red
        }
    }
}



