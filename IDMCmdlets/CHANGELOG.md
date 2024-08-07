# Change log for IDMCmdlets

## 1.0.3.5 July 15, 2024

- Added Compliance policy check
- Added OS release function (https://endoflife.date/docs/api)
- Added ability to easily set compliance policy minimum OS version
- Added ability to easily set the app protection OS launch version
- Updated each cmdleted verbose

## 1.0.3.2 June 12, 2024

- Fixed Assigned user fo device; only grabbed owner

## 1.0.2.9 May 23, 2024

- Added detected apps functions

## 1.0.2.8 April 17, 2024

- Fixed Intunedevice object output. 
- Fixed Azuredevice object output. 

## 1.0.2.7 April 14, 2024

- Added Intune RBAC functions
- Added Azure Group functions
- Cleaned up inconsistencies; added SYNOPSIS to functions
- Fixed Graph conversion to object; check for hashtable, if not use object
- Fixed Get-IDMIntuneAssignments; removed id from uri; already part of batch response
- Added additional graph resources to Get-IDMIntuneAssignments

## 1.0.2.2 April 12, 2024

- Added all switch to get devices. removed IncludeEAS as All is more understandable
- Added user details for Assigned user instead of just userid. Provides a faster way to resolve UPN

## 1.0.2.0 March 9, 2024

- Fixed Autopilot profile expand parameter
- Added ability to assign device id to Autopilot profile id
- Converted all graph hash output to objects
- Fixed device queries based on management agent type; used or operator

## 1.0.1.9 March 8, 2024

- Converted AppSecret to secure string
- Fixed Intune assignments with Authtoken
- Fixed IDMUsers to use multiple CloudEnvironments
- Added new IDM functions to manage stale devices
- Fixed Batch and multithreaded output for graph

## 1.0.1.4 March 7, 2024

- Fixed graph tokens for user and apps; removed auth token requirement
- Added new graph app creation script with appropriate Azure and Intune permissions

## 1.0.1.2 August 2, 2022

- Converted Write-Error to Write-Host for Write-ErrorResponse cmdlet; solved error output
- Addws Split-IDMRequests cmdlet; Fixed assignment output for batch calls of 20 uris at a time.
- Added synopsis to most cmdlets

## 1.0.0.9 August 1, 2022

- Added batch jobs for Devices when using -Expand for Azure requests; speeds up request
- Fixed Intune assignments for each resource; missing batch request

## 1.0.0.9 August 1, 2022

- Fixed Invoke-IDMGraphBatchRequests and Invoke-IDMGraphRequests passthru output for assignments
- Sped up loop using hashtables instead of objects by several seconds
- Fixed Set-IDMResourceFriendlyName ouput; name or friendlyname
- Added IncludeGuest option for Get-IDMAzureUsers; defaults to members only

## 1.0.0.8 July 31, 2022

- Added Graph batch Requests; saves 5 seconds off queries
- Added ErrorAction to each Invoke-Webrequest to stop
- Added IDMHelper.ps1 to support catch errors with rest requests

## 1.0.0.7 July 31, 2022

- Fixed pending actions to default pending output; allow all done action as well with -AllowAll parameter
- Renamed IDM.ps1 to IDMDevice.ps1 to designate its for devices; added IDMusers.ps1 to Users
- Fixed filter query on cmdlets. Nullified the variable so other cmdlets do not use it on accident

## 1.0.0.6 July 30, 2022

- Add Get-IDMDevices (Plural); beta test for nextlink option in graph
- Fixed Expand parameter for Get-IDMDevice and updates Get-IDMAzureDevices; filters same to ensure match when count if more than 1000
- changed Invoke-IDMGraphRequest to support next links. If using -Passthru in current commands, remove it as it will default value output
- Added more Synopsis for cmdlets

## 1.0.0.5 July 27, 2022

- Fixed Get-IDMDevice to pull appropriate list; issue with eas filters
- Cleaned up graph module; output errors instead of write-host
- Added RequiredModules for Azure AD (dll are needed for auth)
- Fixed Intune device actions and removal cmdlets

## 1.0.0.4 July 27, 2022

- Fixed Get-IDMDevice filters; now queries correctly

## 1.0.0.3 July 25, 2022

- Fixed module private data and Helpuri

## 1.0.0.0 July 25, 2022

- Initial upload
