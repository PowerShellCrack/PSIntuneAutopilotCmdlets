#import device
[string]$ResourcePath = ($PWD.ProviderPath, $PSScriptRoot)[[bool]$PSScriptRoot]
$devicList = Import-Csv "$ResourcePath\tests\devicelist.sample.csv"
#$devicList = Import-Csv "$ResourcePath\devicelist.csv"

#Import App Secret
$app = Import-Clixml "$ResourcePath\tests\dtolab_intuneapp_secret.xml"

<#
#set the admin check in regex
^ = starts with
adm- = the prefix for admin accounts
#>
$AdminRegexCheck = '^adm-'

<# TESTS AGAINST REGEX
'adm-frankjones@dtolab.ltd' -match $AdminRegexCheck
'adam.tool@dtolab.ltd' -match $AdminRegexCheck
'admintools@dtolab.ltd' -match $AdminRegexCheck
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

#connect to the graph using app

<#
#NOTE: The following code is used to generate the AES key and encrypted app secret
STEP 1 - Create graph app with Intune permissions as hashtable (for splatting)
$app = New-IDMGraphApp -appNamePrefix "IntuneDeviceManagerApp" -AsHashTable
#save appdetails for later use (STORE SECURELY)
$app | Export-Clixml .\intuneapp_secret.xml

#STEP 2 - create random passphase (256 AES). Save the output as a variable (copy/paste)
#NOTE: this key is unique; the same key must be used to decrypt
$AESKey = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
Write-host ('$AESKey = @(' + ($AESKey -join ",").ToString() + ')')

#STEP 3 - Encrypt password with AES key. Save the output as a variable (copy/paste)
$AppSecret = ConvertTo-SecureString -String $app.AppSecret -AsPlainText -Force | ConvertFrom-SecureString -Key $AESKey
Write-host ('$AppSecretHashed = "' + $AppSecret + '"')
#>

$Global:GraphEndpoint = 'https://graph.microsoft.com'
#From clixml input
#$Global:AuthToken = Get-IDMGraphAppAuthToken @app

$AESKey = '<generated-aes-key (step 1)>'

$TenantId = '<your-tenant-id>'
$AppId = '<your-app-id>'
$AppSecretHashed = '<encrypted-app-secret>'
$Global:AuthToken = Get-IDMGraphAppAuthToken -AppId $AppId -AppSecret $AppSecretHashed -TenantId $TenantId -AESKey $AESKey -CloudEnvironment Public
Connect-IDMGraphApp -AppAuthToken $Global:AuthToken

$AllDevices = Get-IDMDevices

#change assigned profile for eahc device in list
#TEST $item = $devicList[0]
foreach ($item in $devicList)
{
    Write-Host ("Checking device: {0}..." -f $item.DeviceName) -NoNewline -ForegroundColor White
    #must get the device id from the display name
    $DeviceID = $AllDevices | Where-Object { $_.deviceName -eq $item.DeviceName } | Select-Object -ExpandProperty Id

    If($null -eq $DeviceID)
    {
        Write-Host "Device Id not found" -ForegroundColor Red
        Continue #skip to next device
    }Else{
        Write-Host ("Id: {0}" -f $DeviceID) -ForegroundColor Cyan
    }
    
    Write-Host ("  |--Device is assigned to...") -NoNewline -ForegroundColor White
    #get the current assigned user
    $CurrentAssignedUser = Get-IDMDeviceAssignedUser -DeviceId $DeviceID -Passthru
    
    #check if the device is assigned to an admin account
    If($CurrentAssignedUser.userPrincipalName -match $AdminRegexCheck)
    {
        Write-Host ("an admin upn was found: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Yellow
        
        #if true, change the assigned profile
        Write-Host ("  |--re-assigning to: {0}..." -f $item.AssignedUser) -NoNewline -ForegroundColor White
        Try{
            Set-IDMDeviceAssignedUser -DeviceId $DeviceID -UPN $item.AssignedUser
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
            Set-IDMDeviceAssignedUser -DeviceId $DeviceID -UPN $item.AssignedUser
            Write-Host ("Completed!") -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Continue #skip to next device
        }

    }Else{
        
        Write-Host ("a non-admin account: {0}" -f $CurrentAssignedUser.userPrincipalName) -ForegroundColor Yellow
    }
    
}

