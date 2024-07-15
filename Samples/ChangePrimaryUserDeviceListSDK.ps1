<#
.SYNOPSIS
    This script will change the primary user of a list of devices in Azure AD.
.DESCRIPTION
    This script will change the primary user of a list of devices in Azure AD. The script will check if the device is assigned to an admin account. 
.PARAMETER ListFile
    The name of the CSV file containing the list of devices to change. The default value is 'devicelist.example.csv'.
.PARAMETER AssignNonAdminUsers
    Set this switch to re-assign devices that are not assigned to an admin account. If this switch is not set, the script will only re-assign devices that are assigned to an admin account. The default value is $false.
.PARAMETER AdminRegexCheck
    The regex pattern to check for admin accounts. The default value is '^adm-'.
.EXAMPLE
    ChangePrimaryUserDeviceList.ps1 -ListFile devicelist.csv -AssignNonAdminUsers
    This example will change the primary user of the devices in the 'devicelist.csv' file. The script will re-assign devices that are not assigned to an admin account.
.EXAMPLE
    ChangePrimaryUserDeviceList.ps1 -ListFile devicelist.csv
    This example will change the primary user of the devices in the 'devicelist.csv' file. The script will only re-assign devices that are assigned to an admin account.
.NOTES
    Update-MgDeviceManagementManagedDevice NOT WORKING. Errors with: Microsoft.Graph.PowerShell.Models.IMicrosoftGraphUser
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [ArgumentCompleter( {
        param ( $commandName,
                $parameterName,
                $wordToComplete,
                $commandAst,
                $fakeBoundParameters )


        $CsvFiles = Get-Childitem $PSScriptRoot -Filter '*.csv' | Select -ExpandProperty Name

        $CsvFiles | Where-Object {
            $_ -like "$wordToComplete*"
        }

    } )]
    [Alias("config")]
    [string]$ListFile = "devicelist.example.csv",
    [string]$AdminRegexCheck = '^adm-', #regex to check for admin accounts,
    [switch]$AssignNonAdminUsers #set to true to reassign non-admin users. Otherwise assigned users in list are ignored unless there is an admin account assigne to device
)

#set the error action preference
#$ErrorActionPreference = "Stop"

[string]$ResourcePath = ($PWD.ProviderPath, $PSScriptRoot)[[bool]$PSScriptRoot]

$devicList = Import-Csv "$ResourcePath\$ListFile"
#$devicList = Import-Csv "$ResourcePath\devicelist.csv"

$LogfileName = "ChangePrimaryUserDeviceList-$(Get-Date -Format 'yyyy-MM-dd_Thh-mm-ss-tt').log"
New-Item "$ResourcePath\Logs" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Try{Start-transcript "$ResourcePath\Logs\$LogfileName" -ErrorAction Stop}catch{Start-Transcript "$ResourcePath\$LogfileName"}


#IMPORT MODULES
#==============================================

$modules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Beta.DeviceManagement',
    'Microsoft.Graph.Beta.Users'
)

foreach ($module in $modules){
    Write-Host ("Checking for installed module: {0}..." -f $module) -ForegroundColor White
    If((Find-Module $module).Version -in (Get-InstalledModule $module -AllVersions).version)
    {
        Write-Host ("  |--Version [{0}] installed" -f (Get-InstalledModule $module -AllVersions).version) -ForegroundColor Green
    }
    Else{
        Write-Host ("  |--Updating, please wait..." )-ForegroundColor Yellow -NoNewline
        Install-Module -Name $module -AllowClobber -Force
        Write-Host "Done" -ForegroundColor Green
    }
}
#MAIN
#==============================================


Write-Host '----------------------------------------' -ForegroundColor White
#connect to the graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor White -NoNewline
Connect-MgGraph -NoWelcome
$context = Get-MgContext
write-host ("Connected as: {0}" -f $context.Account) -ForegroundColor Green
Write-Verbose ("{0}" -f ($context | out-string))

#Get all devices
Write-Host "Getting all devices..." -ForegroundColor White
$AllDevices = Get-MgBetaDeviceManagementManagedDevice -All -Verbose:$VerbosePreference
write-host ("  |--{0} devices found" -f $AllDevices.Count) -ForegroundColor Green

Write-Host '----------------------------------------' -ForegroundColor White
#change assigned profile for eahc device in list
#TEST $item = $devicList[0]
foreach ($item in $devicList)
{
    Write-Host ("Getting device details for: {0}..." -f $item.DeviceName) -NoNewline -ForegroundColor White
    #must get the device id from the display name
    $DeviceID = $AllDevices | Where-Object { $_.deviceName -eq $item.DeviceName } | Select-Object -ExpandProperty Id
    Write-Verbose ("{0}" -f ($AllDevices | Where-Object { $_.deviceName -eq $item.DeviceName } | out-string))
    If($null -eq $DeviceID)
    {
        Write-Host "Device Id not found" -ForegroundColor Red
        Continue #skip to next device
    }Else{
        Write-Host ("Id: {0}" -f $DeviceID) -ForegroundColor Cyan
    }
    
    Write-Host ("  |--Device is assigned to...") -NoNewline -ForegroundColor White
    #get the current assigned user
    $CurrentAssignedUser = Get-MgBetaDeviceManagementManagedDeviceUser -ManagedDeviceId $DeviceID -Verbose:$VerbosePreference
    $NewAssignedUser = Get-MgBetaUser -ConsistencyLevel eventual -Filter "startsWith(userPrincipalName, '$($item.AssignedUser)')"
    Write-Verbose ("{0}" -f ($CurrentAssignedUser | out-string))
    #check if the device is assigned to an admin account
    If($CurrentAssignedUser.userPrincipalName -match $AdminRegexCheck)
    {
        Write-Host ("an admin upn was found: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Yellow
        
        #if true, change the assigned profile
        Write-Host ("  |--re-assigning to: {0}..." -f $item.AssignedUser) -NoNewline -ForegroundColor White
        Try{
            Update-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $DeviceID -Users $NewAssignedUser -Verbose:$VerbosePreference
            Write-Host ("Completed!") -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Continue #skip to next device
        }
        
    }ElseIf($CurrentAssignedUser.userPrincipalName -eq $item.AssignedUser)
    {
        Write-Host ("the correct upn: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Green
    
    }ElseIf( ($CurrentAssignedUser.userPrincipalName -ne $item.AssignedUser) -and $AssignNonAdminUsers )
    {
        
        Write-Host ("a different upn is assigned: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Yellow
        
        #if true, change the assigned profile
        Write-Host ("  |--re-assigning to: {0}..." -f $item.AssignedUser) -NoNewline -ForegroundColor White
        Try{
            Update-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $DeviceID -Users $NewAssignedUser -Verbose:$VerbosePreference
            Write-Host ("Completed!") -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Continue #skip to next device
        }

    }Else{
        
        Write-Host ("a non-admin account: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Yellow
    }
    
}


Stop-Transcript