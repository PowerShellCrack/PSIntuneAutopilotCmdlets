# Change log for IDMCmdlets


## 1.0.0.7 July 31, 2022

- Fixed pending actions to default pending output; allow all done action as well with -AllowAll parameter
- Renamed IDM.ps1 to IDMDevice.ps1 to desgniate its for devices; added IDMusers.ps1 to Users
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
