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

#import app secret
$app = Import-Clixml .\dtolab_intuneapp_secret.xml
$AppSecret = ConvertFrom-SecureString -SecureString $app.AppSecret -AsPlainText

$Global:GraphEndpoint = 'https://graph.microsoft.com'
$Global:AuthToken = Get-IDMGraphAppAuthToken @app
Connect-IDMGraphApp -AppAuthToken $Global:AuthToken

#Within Autopilot:
$AppId = '009bbee5-3ff5-4fe1-a2bd-2e0cec916eac'
#STEP 1 - create random passphase (256 AES). Save the output as a variable (copy/paste)
#NOTE: this key is unique; the same key must be used to decrypt
$AESKey = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
Write-host ('$AESKey = @(' + ($AESKey -join ",").ToString() + ')')

$AESKey = @(28,89,174,82,179,115,230,166,2,32,44,75,32,210,236,121,46,61,151,176,111,48,49,108,251,205,33,18,11,178,25,121)
#STEP 2 - Encrypt password with AES key. Save the output as a variable (copy/paste)
$AppSecret = ConvertTo-SecureString -String $AppSecret -AsPlainText -Force | ConvertFrom-SecureString -Key $AESKey
Write-host ('$ADEncryptedPassword = "' + $AppSecret + '"')

#STEP 3 - Store as useable credentials; converts encrypted key into secure key for use (used in the script)
$SecurePass = $AppSecret  | ConvertTo-SecureString -Key $AESKey
$credential = New-Object System.Management.Automation.PsCredential($AppId, $SecurePass)

#STEP 4 - Test password output (clear text) from creds
$credential.GetNetworkCredential().password