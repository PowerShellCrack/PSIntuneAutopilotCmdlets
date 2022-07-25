# Cmdlets for Intune & Autopilot device management

## Prerequisites

No prerequisites are needed

## Install

```powershell
Install-Module IDMCmdlets -Force
Import-Module IDMCmdlets
```

## Cmdlets

### IDMGraph.ps1
- **Connect-IDMGraphApp** : Authenticates to the Graph API using app
- **Get-IDMGraphAuthToken** : Authenticate with the Graph API REST interface
- **Update-IDMGraphAccessToken** : Refreshes an access token
- **Invoke-IDMGraphRequests** :  Invoke multiple graph requests in in a multithreaded runspace pool to speed up response

### IDM.ps1

- **Get-IDMDevice** : Retrieves Intune Managed Devices; use expand to get association with Azure AD (eg. Get-IDMDevice -Expand)
- **Get-IDMAzureDevices** : Retrieves Azure Devices
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

### Autopilot.ps1
- **Get-IDMAutopilotProfile** : Retrieves Windows Autopilot profiles
- **Get-IDMAutopilotDevice** : Retrieves devices currently registered with Windows Autopilot.
- **Set-IDMAutopilotDeviceTag** : Updates grouptag for Autopilot device


## Examples

```powershell
install IDMCmdlets
$Global:AuthToken = Connect-IDMGraphApp -Tenant 0ad2375d-0906-41d5-9563-1994db1a70f9 -AppId f96b2862-9dcd-468e-8935-a86e575f814a -AppSecret "j0H8Q~X7YBLFYD6YoUBL2gPLE37yg5k5WATmGcgB"

$Global:Authtoken = Get-IDMGraphAuthToken -User $MSgraph.UPN

Get-IDMDevice -Platform Windows

Get-IDMIntuneAssignments -Target Devices -TargetId 'afb8aa9a-c4cf-48aa-ad7b-ec60180ea787' -IncludePolicySetInherits

Get-IDMIntuneAssignments -Target Users -TargetId '4d20ea83-c825-46d6-a07f-ce97cfe19b6b' -IncludePolicySetInherits
```
