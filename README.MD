# Cmdlets for Intune & Autopilot device management

## Prerequisites

- Az.Accounts*
- Microsoft.Graph.Authentication*
- Microsoft.Graph.Applications*

> *If creating an app using module

## Install

```powershell
Install-Module IDMCmdlets -Force
```

## Cmdlets

### Intune

- **New-IDMGraphApp** : Creates an Application with appropriate permissions
- **Update-IDMGraphApp** : Updates an application secret or permissions
- **Get-IDMGraphAppAuthToken** : Grabs the Graph token from app
- **Connect-IDMGraphApp** : Authenticates to the Graph API using app
- **Update-IDMGraphAccessToken** : Refreshes an access token
- **Invoke-IDMGraphRequests** :  Invoke multiple graph requests in in a multithreaded runspace pool to speed up response
- **Get-IDMDevice** : Retrieves Intune Managed Devices; use expand to get association with Azure AD (eg. Get-IDMDevice -Expand)
- **Get-IDMStaleDevices** : Retrieves Intune Stale Devices
- **Remove-IDMStaleDevices** : Removes stale devices from Intune
- **Get-IDMDevicePendingActions** : Retrieves a Managed Device pending Actions
- **Get-IDMDeviceAssignedUser** : Retrieves Managed Device assigned username
- **Get-IDMDeviceAADUser** : Retrieves Azure AD User info
- **Get-IDMDeviceCategory** : Retrieves Device Category details
- **Set-IDMDeviceCategory** : Sets Device Category
- **Invoke-IDMDeviceAction** : initiate a Intune device action (actions are: RemoteLock,ResetPasscode,Wipe,Retire,Delete,Sync,Rename)
- _Remove-IDMDeviceRecords_ *
- _Get-IDMIntuneAssignments_ *
- _Set-IDMResourceFriendlyName_ *
- _Set-IDMResourceFriendlyType_ *

> \* Cmdlets still a work-in-progress

### Azure

- **Get-IDMAzureDevices** : Retrieves Azure Devices
- **Get-IDMAzureStaleDevices** : Retrieves Azure Stale Devices
- **Get-IDMAzureDeviceExtension** : Get Azure Device extensions
- **Set-IDMAzureDeviceExtension** : Sets Azure Device extensions

### Autopilot

- **Get-IDMAutopilotProfile** : Retrieves Windows Autopilot profiles
- **Get-IDMAutopilotDevice** : Retrieves devices currently registered with Windows Autopilot.
- **Set-IDMAutopilotDeviceTag** : Updates grouptag for Autopilot device

## Clouds Supported

- Public (IL3)
- Azure Government (IL4)
- Azure DOD (IL5)

## Examples #1

```powershell
Install-Module Az.Accounts
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Applications
Install-Module IDMCmdlets

#create graph app with Intune permissions as hashtable (for splatting)
$app = New-IDMGraphApp -appNamePrefix "IntuneDeviceManagerApp" -AsHashTable

#save appdetails for later use
$app | Export-Clixml .\intuneapp_secret.xml
```

## Examples #2

```powershell
Install-Module IDMCmdlets

$app = Import-Clixml .\intuneapp_secret.xml

#import the app as splat for all parameters to get authtoken header
$Global:AuthToken = Get-IDMGraphAppAuthToken @app
Connect-IDMGraphApp -AppAuthToken $Global:AuthToken

#perform actions (can also call other Invoke-MgGraphRequests)
Get-IDMDevice -Platform Windows

Get-IDMIntuneAssignments -Target Devices -TargetId 'b305693e-4140-40e5-86c8-67b8cb1cc822' -IncludePolicySetInherits

Get-IDMIntuneAssignments -Target Users -TargetId 'c3aa4156-7242-44f8-a29c-0eaf03405de6' -IncludePolicySetInherits

```

## Examples #3

```powershell
Install-Module IDMCmdlets

#import app details
$app = Import-Clixml .\intuneapp_secret.xml

#Add permissions to app
Update-IDMGraphApp -AppId $app.AppId -Permissions "Group.ReadWrite.All","GroupMember.ReadWrite.All" -TenantID $app.TenantID

#add new secret to app
$app = Update-IDMGraphApp -AppId $app.AppId -NewSecret -TenantID $app.TenantID -AsHashTable

#export appdetails
$app | Export-Clixml .\intuneapp_secret.xml
```

## Sample Scripts

There are additional sample scripts in the Sample Folders. This will grow in time. 

# DISCLAIMER

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.