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

- **New-IDMGraphApp** : Creates an Application with appropiate permissions
- **Connect-IDMGraphApp** : Authenticates to the Graph API using app
- **Get-IDMGraphAppAuthToken** : Grabs the Graph token from app
- **Update-IDMGraphAccessToken** : Refreshes an access token
- **Invoke-IDMGraphRequests** :  Invoke multiple graph requests in in a multithreaded runspace pool to speed up response
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

$app = New-IDMGraphApp -appNamePrefix "IntuneDeviceManagerApp" -AsHashTable
$token = Get-IDMGraphAppAuthToken @app -ReturnToken
Connect-IDMGraphApp -AppAuthToken $token

Get-IDMDevice -Platform Windows

Get-IDMIntuneAssignments -Target Devices -TargetId 'afb8aa9a-c4cf-48aa-ad7b-ec60180ea787' -IncludePolicySetInherits

Get-IDMIntuneAssignments -Target Users -TargetId '4d20ea83-c825-46d6-a07f-ce97cfe19b6b' -IncludePolicySetInherits
```

## Examples #2

```powershell
Install-Module IDMCmdlets

$app = New-IDMGraphApp -CloudEnvironment USGov -appNamePrefix "IntuneDeviceManagerApp" -AsHashTable
$token = Get-IDMGraphAppAuthToken @app -ReturnToken
Connect-IDMGraphApp -CloudEnvironment USGov -AppAuthToken $token

Get-IDMDevice -Platform Windows

Get-IDMIntuneAssignments -Target Devices -TargetId 'b305693e-4140-40e5-86c8-67b8cb1cc822' -IncludePolicySetInherits

Get-IDMIntuneAssignments -Target Users -TargetId 'c3aa4156-7242-44f8-a29c-0eaf03405de6' -IncludePolicySetInherits
```