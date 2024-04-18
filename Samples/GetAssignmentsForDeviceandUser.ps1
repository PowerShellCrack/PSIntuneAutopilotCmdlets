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

$AllDevices = Get-IDMDevice -Expand -All

$UserID = (Get-IDMAzureUser -userPrincipalName $AllDevices[1].userPrincipalName).id

Get-IDMIntuneAssignments -TargetSet @{devices= $AllDevices[1].deviceId;Users=$UserID}
