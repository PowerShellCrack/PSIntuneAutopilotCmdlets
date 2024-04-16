#import device
[string]$ResourcePath = ($PWD.ProviderPath, $PSScriptRoot)[[bool]$PSScriptRoot]
$devicList = Import-Csv "$ResourcePath\tests\devicelist.sample.csv"
#$devicList = Import-Csv "$ResourcePath\devicelist.csv"

<#
#set the admin check in regex
^ = starts with
adm- = the prefix for admin accounts
#>
$admincheck = '^adm-'

<# TESTS AGAINST REGEX
'adm-frankjones@dtolab.ltd' -match $admincheck
'adam.tool@dtolab.ltd' -match $admincheck
'admintools@dtolab.ltd' -match $admincheck
#>

#Set to true to reassign non-admin users. 
#$Otherwise assigned users in list are ignored unless there is an admin account assigne to device
$AssignNonAdminUsers = $false

#IMPORT MODULES
#==============================================

Install-Module Az.Accounts
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Applications
Install-Module IDMCmdlets

#MAIN
#==============================================
#set the graph endpoint
$Global:GraphEndpoint = 'https://graph.microsoft.com'

#connect to the graph
Connect-MgGraph

$AllDevices = Get-IDMDevices

#change assigned profile for eahc device in list
#TEST $Device = $devicList[0]
foreach ($Device in $devicList)
{
    Write-Host ("Checking device: {0}..." -f $Device.DeviceName) -NoNewline -ForegroundColor White
    #must get the device id from the display name
    $DeviceID = $AllDevices | Where-Object { $_.deviceName -eq $Device.DeviceName } | Select-Object -ExpandProperty Id

    If($null -eq $DeviceID)
    {
        Write-Host "Device Id not found" -ForegroundColor Red
        Continue #skip to next device
    }Else{
        Write-Host ("Id: {0}" -f $DeviceID) -ForegroundColor Cyan
    }
    
    Write-Host ("  |--Device is assigned to...") -NoNewline -ForegroundColor White
    #get the current assigned user
    $CurrentUser = Get-IDMDeviceAssignedUser -DeviceId $DeviceID -Passthru
    
    #check if the device is assigned to an admin account
    If($CurrentUser.userPrincipalName -match $admincheck)
    {
        Write-Host ("an admin account: {0}" -f $CurrentUser.userPrincipalName) -ForegroundColor Yellow
        
        #if true, change the assigned profile
        Write-Host ("  |--re-assigning to: {0}..." -f $Device.AssignedUser) -NoNewline -ForegroundColor White
        Try{
            Set-IDMDeviceAssignedUser -DeviceId $DeviceID -UPN $Device.AssignedUser
            Write-Host ("Completed!") -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Continue #skip to next device
        }
        
    }ElseIf($CurrentUser.userPrincipalName -eq $Device.AssignedUser)
    {
        Write-Host ("the correct upn: {0}" -f $CurrentUser.userPrincipalName) -ForegroundColor Green
    
    }ElseIf( ($CurrentUser.userPrincipalName -ne $Device.AssignedUser) -and $AssignNonAdminUsers )
    {
        
        Write-Host ("an another upn: {0}" -f $CurrentUser.userPrincipalName) -ForegroundColor Yellow
        
        #if true, change the assigned profile
        Write-Host ("  |--re-assigning to: {0}..." -f $Device.AssignedUser) -NoNewline -ForegroundColor White
        Try{
            Set-IDMDeviceAssignedUser -DeviceId $DeviceID -UPN $Device.AssignedUser
            Write-Host ("Completed!") -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Continue #skip to next device
        }

    }Else{
        
        Write-Host ("to non-admin account: {0}" -f $CurrentUser.userPrincipalName) -ForegroundColor White
    }
    
}