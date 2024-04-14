Function Get-IDMRole{

    <#
    .SYNOPSIS
    This function is used to get RBAC Role Definitions from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Definitions

    .PARAMETER Name
    Specify the display name of the role definition

    .PARAMETER Assignments
    Specify to include role assignments

    .PARAMETER IncludeBuiltin
    Specify to include builtin roles

    .EXAMPLE
    Get-IDMRole
    Returns all custom RBAC Role Definitions configured in Intune

    .EXAMPLE
    Get-IDMRole -IncludeBuiltin
    Returns all RBAC Role Definitions configured in Intune including builtin

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [String]$Name,

        [Parameter(Mandatory=$false)]
        [switch]$Assignments,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBuiltin
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    try {

        if($Name){

            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
            $Result = (Invoke-MgGraphRequest -Uri $uri -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and $_.isBuiltInRoleDefinition -eq $IncludeBuiltin }
        }
        else {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
            $Result = (Invoke-MgGraphRequest -Uri $uri -Method Get).Value
        }


        If($Assignments){
            #TEST $Def = $Result[0]
            Foreach($Def in $Result){
                $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource('$($Def.id)')?`$expand=roleassignments"
                (Invoke-MgGraphRequest -Uri $uri -Method Get).roleAssignments
            }
        }
        Else{
            return $Result
        }
    }

    catch {
        Write-ErrorResponse($_)
    }

}

Function New-IDMRole{
    <#
    .SYNOPSIS
    This function is used to add an RBAC Role Definitions from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and adds an RBAC Role Definitions

    .PARAMETER JsonDefinition
    Specify the JSON definition of the role definition

    .EXAMPLE
    New-IDMRole -JsonDefinition $JSON

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0

    .LINK
    Test-JSON
    #>

    [cmdletbinding()]
    param(
        [ValidateScript({Test-JSON $_})]
        [Parameter(Mandatory=$true)]
        [string]$JsonDefinition
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JsonDefinition
    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Set-IDMRole{
    <#
    .SYNOPSIS
    This function is used to set the RBAC Role Definitions from an existing Intune Role

    .DESCRIPTION
     This function is used to set the RBAC Role Definitions from the Graph API REST interface

    .PARAMETER Id
    Specify the Id of the role definition

    .PARAMETER JsonDefinition
    Specify the JSON definition of the role definition

    .PARAMETER DisplayName
    Specify the display name of the role definition

    .PARAMETER Description
    Specify the description of the role definition

    .EXAMPLE
    Set-IDMRole -JsonDefinition $JSON

    .EXAMPLE
    Set-IDMRole -Id '5d789e69-e99d-40dc-aaea-02bddfb2a8bc' -JsonDefinition $JSON

    .EXAMPLE
    Set-IDMRole -Id '5d789e69-e99d-40dc-aaea-02bddfb2a8bc' -JsonDefinition $JSON -DisplayName "Test"

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-update?view=graph-rest-beta

    .LINK
    Test-JSON
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Id,

        [ValidateScript({Test-JSON $_})]
        [Parameter(Mandatory=$true)]
        [string]$JsonDefinition,

        [Parameter(Mandatory=$false)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    #build Object for JSON body
    $RoleObject = $JsonDefinition | ConvertFrom-Json

    #TEST $RoleObject = $RoleDefinition | ConvertFrom-Json
    If($DisplayName){
        $RoleObject.displayName = $DisplayName
    }
    If($Description){
        $RoleObject.description = $Description
    }
    #build Json body from object
    $JsonDefinition = $RoleObject | ConvertTo-Json -Depth 10
    #test $id='5d789e69-e99d-40dc-aaea-02bddfb2a8bc'
    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$($Id)"
        Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JsonDefinition
    }
    catch {
        Write-ErrorResponse($_)
    }
}

Function Remove-IDMRole{
    <#
    .SYNOPSIS
    This function is used to remove an RBAC Role Definitions from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and removes an RBAC Role Definitions

    .PARAMETER DisplayName
    Specify the display name of the role definition

    .PARAMETER Id
    Specify the Id of the role definition

    .EXAMPLE
    Remove-IDMRole -DisplayName "Test"

    .EXAMPLE
    Remove-IDMRole -Id '5d789e69-e99d-40dc-aaea-02bddfb2a8bc'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-delete?view=graph-rest-beta

    .LINK
    Get-IDMRole
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$Id
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    if($DisplayName){
        $RoleId = (Get-IDMRole -Name $DisplayName) | Where IsBuiltin -ne $true | Select -ExpandProperty id
    }Else{
        #$DisplayName = (Get-IDMRole -Id $Id).displayName
        $RoleId = $Id
    }

    If($RoleId)
    {
        Write-verbose ("Role [{0}] has an Id of [{1}]" -f $DisplayName,$RoleId)
    }
    Else{
        Write-verbose ("No Role by the name of [{0}] or is a builtin role" -f $DisplayName)
        Break
    }

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource('$($RoleId)')"
        Invoke-MgGraphRequest -Uri $uri -Method Delete
    }
    catch {
        Write-ErrorResponse($_)
    }
}




Function Get-IDMScopeTag{

    <#
    .SYNOPSIS
    This function is used to get scope tags using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets scope tags

    .PARAMETER DisplayName
    Specify the display name of the scope tag

    .PARAMETER Id
    Specify the Id of the scope tag

    .EXAMPLE
    Get-IDMScopeTag -DisplayName "Test"
    Gets a scope tag with display Name 'Test'

    .EXAMPLE
    Get-IDMScopeTag -Id 1
    Gets a scope tag with Id 1

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-get?view=graph-rest-beta
    #>

    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [int32]$Id
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    try {
        if($DisplayName){
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)`?`$filter=displayName eq '$DisplayName'"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop
        }
        elseif($Id){
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)`?`$filter=id eq '$Id'"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop
        }
        else {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop

        }
        return $Result.Value
    }
    catch {
        Write-ErrorResponse($_)
    }
}

Function New-IDMScopeTag{
    <#
    .SYNOPSIS
    This function is used to add a scope tag using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and adds a scope tag

    .PARAMETER DisplayName
    Specify the display name of the scope tag

    .PARAMETER Description
    Specify a description of the scope tag

    .EXAMPLE
    New-IDMScopeTag -DisplayName "Test"

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-post?view=graph-rest-beta

    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$False)]
        [string]$Description
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleScopeTag"
    $object | Add-Member -MemberType NoteProperty -Name "displayName" -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name "description" -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name "isBuiltIn" -Value $false
    $JSON = $object | ConvertTo-Json

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/"
        $result = Invoke-MgGraphRequest -Method Post -Uri $uri -Body $JSON -ErrorAction Stop
        return $result.id
    }
    catch {
        Write-ErrorResponse($_)
    }

}

Function Remove-IDMScopeTag{
    <#
    .SYNOPSIS
    This function is used to remove a scope tag using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and removes a scope tag

    .PARAMETER DisplayName
    Specify the display name of the scope tag to remove

    .EXAMPLE
    Remove-IDMScopeTag -DisplayName "Test"

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-delete?view=graph-rest-beta

    .LINK
    Get-IDMScopeTag
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        $DisplayName
    )

    $graphApiVersion = "beta"
    $Resource = "/deviceManagement/roleScopeTags"

    $ScopeTagId = (Get-IDMScopeTag -DisplayName $DisplayName).id

    If($ScopeTagId -and ($DisplayName -ne 'default') )
    {
        Write-verbose ("Scope tag [{0}] has an Id of [{1}]" -f $DisplayName,$ScopeTagId)
    }
    Else{
        Write-verbose ("No Scope tag by the name of [{0}] was found" -f $DisplayName)
        Break
    }

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource('$($ScopeTagId)')"
        Invoke-MgGraphRequest -Uri $uri -Method Delete
    }

    catch {
        Write-ErrorResponse($_)
    }
}

Function Invoke-IDMRoleAssignment{

    <#
    .SYNOPSIS
    This function is used to set an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and sets and assignment for an RBAC Role

    .PARAMETER Id
    specify a ID of the role Assignment.

    .PARAMETER DisplayName
    specify a display or friendly name of the role Assignment.

    .PARAMETER Description
    Specify a description of the role Assignment.

    .PARAMETER MemberGroupId
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupId
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .EXAMPLE
    Invoke-IDMRoleAssignment -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupId
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/resources/intune-rbac-roleassignment?view=graph-rest-beta
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Id,

        [Parameter(Mandatory=$true)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory=$true)]
        [string[]]$MemberGroupId,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupId
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"


    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'id' -Value ""
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'members' -Value @($MemberGroupId)
    $object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($TargetGroupId)
    $object | Add-Member -MemberType NoteProperty -Name 'roleDefinition@odata.bind' -Value "$Global:GraphEndpoint/$graphApiVersion/deviceManagement/roleDefinitions('$Id')"
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
        $Result = Invoke-MgGraphRequest -Method Post -Uri $uri -Body $JSON -ErrorAction Stop
        return $Result

    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Update-IDMRoleAssignmentGroups{

    <#
    .SYNOPSIS
    This function is used to update an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and update an assignment for an RBAC Role

    .PARAMETER RoleDefinitionId
    Role Definition Id. Use Get-IDMRole to get definition id

    .PARAMETER AssignmentId
    Assignment Id. Use  Get-IDMRoleAssignmentGroups to get assignment id

    .PARAMETER MemberGroupIds
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupIds
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER AllDevices
    Assigns to all devices

    .PARAMETER AllUsers
    Assigns to all users

    .EXAMPLE
    Update-IDMRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -TargetGroupIds $TargetGroupIds
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .EXAMPLE
    Update-IDMRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -AllUsers

    .EXAMPLE
    Update-IDMRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -AllDevices

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-update?view=graph-rest-beta
    #>

    [CmdletBinding(DefaultParameterSetName = 'Targeted')]
    param
    (
        [Parameter(Mandatory=$true)]
        $RoleDefinitionId,

        [Parameter(Mandatory=$true)]
        $AssignmentId,

        [Parameter(Mandatory=$false)]
        [string[]]$MemberGroupIds,

        [Parameter(Mandatory = $true, ParameterSetName = 'Targeted')]
        [string[]]$TargetGroupIds,

        [Parameter(Mandatory=$false)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [switch]$AllDevices,

        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [switch]$AllUsers
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"


    #build Object for JSON body
    If($AllDevices -and $AllUsers){
        $ScopeType = 'allDevicesAndLicensedUsers'
    }
    ElseIf($AllDevices){
        $ScopeType = 'allDevices'
    }
    ElseIf($AllUsers){
        $ScopeType = 'allLicensedUsers'
    }
    Else{
        $ScopeType = 'resourceScope'
    }

    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.groupAssignmentTarget"
    #$object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleAssignment"
    If($DisplayName){$object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName}
    If($Description){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description}
    If($MemberGroupIds.count -gt 0){$object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($MemberGroupIds)}
    If($AllDevices -or $AllUsers){
        $object | Add-Member -MemberType NoteProperty -Name 'scopeType' -Value $ScopeType
        #$object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value ''
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value @($TargetGroupIds)
    }
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$RoleDefinitionId/roleAssignments/$AssignmentId"
        $Result = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body $JSON -ErrorAction Stop
        return $Result

    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Invoke-IDMRoleAssignmentAll{

    <#
    .SYNOPSIS
    This function is used to set an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and sets and assignment for an RBAC Role

    .PARAMETER Id
    specify a ID of the role Assignment.

    .PARAMETER DisplayName
    Specify a display or friendly name of the role Assignment.

    .PARAMETER Description
    Specify a description of the role Assignment.

    .PARAMETER MemberGroupIds
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupIds
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER AllDevices
    Assigns to all devices

    .PARAMETER AllUsers
    Assigns to all users

    .EXAMPLE
    Invoke-IDMRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -TargetGroupIds $TargetGroupIds
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .EXAMPLE
    Invoke-IDMRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -AllUsers

    .EXAMPLE
    Invoke-IDMRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -AllDevices

    .NOTES

    REFERENCE: https://docs.microsoft.com/en-us/graph/api/resources/intune-rbac-roleassignment?view=graph-rest-beta
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Id,

        [Parameter(Mandatory=$true)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory=$true)]
        [string[]]$MemberGroupIds,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupIds,

        [switch]$AllDevices,

        [switch]$AllUsers
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"


    #build Object for JSON body
    If($AllDevices -and $AllUsers){
        $ScopeType = 'allDevicesAndLicensedUsers'
    }
    ElseIf($AllDevices){
        $ScopeType = 'allDevices'
    }
    ElseIf($AllUsers){
        $ScopeType = 'allLicensedUsers'
    }
    Else{
        $ScopeType = 'resourceScope'
    }

    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleAssignment"
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($MemberGroupIds)
    $object | Add-Member -MemberType NoteProperty -Name 'scopeType' -Value $ScopeType
    If($AllDevices -or $AllUsers){
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value ''
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value @($TargetGroupIds)
    }
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$Id/roleAssignments"
        $Result = Invoke-MgGraphRequest -Method Post -Uri $uri -Body $JSON -ErrorAction Stop
        return $Result

    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Get-IDMScopeTagAssignment{
    <#
    .DESCRIPTION
    This function updates the scope tag for an assignment

    .PARAMETER ScopeTagId
    Gets the assignment of scope tag using Id

    .PARAMETER ScopeTagName
    Gets the assignment of scope tag using Name

    .EXAMPLE
    Get-IDMScopeTagAssignment -ScopeTagId 1

    .EXAMPLE
    Get-IDMScopeTagAssignment -ScopeTagName SiteRegion1

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-get?view=graph-rest-beta

    .LINK
    Get-IDMScopeTag
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$ScopeTagId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$ScopeTagName
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    If($ScopeTagName){
        $ScopeTagId = (Get-IDMScopeTag -DisplayName $ScopeTagName).id
    }

    If($ScopeTagId){
        $ScopeTagName = (Get-IDMScopeTag -Id $ScopeTagId).DisplayName
    }
    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$ScopeTagId/assignments"
        $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop
        If($Result){
            $ResultObj = "" | Select ScopeName,ScopeId,AssignmentId,GroupId
            $ResultObj.ScopeName = $ScopeTagName
            $ResultObj.ScopeId = $ScopeTagId
            $ResultObj.AssignmentId = $Result.Value.id
            $ResultObj.GroupId = $Result.Value.target.groupId

            Return $ResultObj
        }
    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Invoke-IDMScopeTagAssignment{
    <#
    .DESCRIPTION
    This function assigns an Azure Ad group to tag

    .PARAMETER ScopeTagId
    Scope Tag Id. Use Get-IDMScopeTag to get id

    .PARAMETER TargetGroupIds
    Array of Group Ids to assign to the tag

    .EXAMPLE
    Invoke-IDMScopeTagAssignment -ScopeTagId 1 -TargetGroupIds @('57','58')
    This example assigns the group ids to the scope tag id

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-assign?view=graph-rest-beta

    .LINK
    Get-IDMScopeTag
    ConvertFrom-Json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$ScopeTagId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$ScopeTagName,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupIds
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    If($ScopeTagName){
        $ScopeTagId = (Get-IDMScopeTag -DisplayName $ScopeTagName).id
    }

    $AutoTagObject = @()
    foreach ($TargetGroupId in $TargetGroupIds)
    {
        #Build custom object for assignment
        $AssignmentProperties = "" | Select id,target
        $AssignmentProperties.id = ($TargetGroupId + '_' + $ScopeTagId)


        #Build custom object for target
        $targetProperties = "" | Select "@odata.type",deviceAndAppManagementAssignmentFilterId,deviceAndAppManagementAssignmentFilterType,groupId
        $targetProperties."@odata.type" = "microsoft.graph.groupAssignmentTarget"
        $targetProperties.deviceAndAppManagementAssignmentFilterId = $null
        $targetProperties.deviceAndAppManagementAssignmentFilterType = 'none'
        $targetProperties.groupId = $TargetGroupId

        #add target object to assignment
        $AssignmentProperties.target = $targetProperties

        $AutoTagObject += $AssignmentProperties

    }
    #build body object
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($AutoTagObject)
    $JSON = $object | ConvertTo-Json -Depth 10

   try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$ScopeTagId/assign"
        $Result = Invoke-MgGraphRequest -Method Post -Uri $uri -Body $JSON -ErrorAction Stop
        Return $Result.value.id
    }
    catch {
        Write-ErrorResponse($_)
    }
}




Function Get-IDMRoleAssignmentGroups{
    <#
    .DESCRIPTION
    This function gets the Groups for a Role assignment

    .PARAMETER RoleDefinitionId
    Role Definition Id. Use Get-IDMRole to get definition id

    .PARAMETER RoleAssignmentId
    Assignment Id. Use  Get-IDMScopeTagAssignment to get assignment id

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-get?view=graph-rest-beta

    .LINK
    Get-IDMScopeTagAssignment
    Get-IDMRole
    #>
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [string]$Id
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"

    try {
        if($DisplayName){
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)`?`$filter=displayName eq '$DisplayName'"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop
        }
        elseif($Id){
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)`?`$filter=id eq '$Id'"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop
        }
        else {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
            $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop

        }
        return $Result.Value
    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Invoke-IDMRoleAssignmentScopeTag{
    <#
    .DESCRIPTION
    This function updates the scope tag for a Role assignment

    .PARAMETER AssignmentId
    Role assignment Id. Use Get-IDMRoleAssignmentScopeTag to get id

    .PARAMETER ScopeTagIds
    Array of Tag Ids to set. Use Get-IDMScopeTag to get id's

    .EXAMPLE
    Invoke-IDMRoleAssignmentScopeTag -AssignmentId 'c08c5ab7-b73e-4c4f-a12b-00bb9d1b7262' -ScopeTagIds @('57','58')

    This example updates the scope tags ids for the Assignment

    .LINK
    Get-IDMRoleAssignmentScopeTag
    Get-IDMScopeTag
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AssignmentId,

        [Parameter(Mandatory=$true)]
        [string[]]$ScopeTagIds
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"

    #build Object for JSON body
    foreach ($ScopeTagid in $ScopeTagids) {
        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value "$Global:GraphEndpoint/$graphApiVersion/deviceManagement/roleScopeTags('$ScopeTagId')"
        $JSON = $object | ConvertTo-Json

        try {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$AssignmentId/roleScopeTags/`$ref"
            $Null = Invoke-MgGraphRequest -Method Post -Uri $uri  -Body $JSON
        }
        catch {
            Write-ErrorResponse($_)
        }
    }

}



Function New-IDMRoleDefinition{
    <#
    .SYNOPSIS
    Creates a roleDefinition object for Intune

    .DESCRIPTION
    This function creates a roleDefinition object for Intune

    .PARAMETER DisplayName
    Specifies a display name.

    .PARAMETER Description
    Specifies a description.

    .PARAMETER PermissionSet
    Specify built-in role permissions.

    .PARAMETER RolePermissions
    Specify role permissions dot format. Can be in an array @()

    .PARAMETER ScopeTags
    Specify Tag integer Ids. Can be in an array @()

    .PARAMETER AsJson
    returns json format of definition

    .EXAMPLE
    New-IDMRoleDefinition -DisplayName "Reporting role" -AsJson
    Generates a new Role definition object with empty permissions sets in json format

    .EXAMPLE
    New-IDMRoleDefinition -DisplayName "Reporting role" -Description "Powershell create Reporting role" -PermissionSet Report-Only -ScopeTags @(1,2) -AsJson
    Generates a new Role definition object with report only permissions with scope tags presets in json format

    .EXAMPLE
    New-IDMRoleDefinition -DisplayName "new role" -Description "Testing powershell automation" -PermissionSet Report-Only -ScopeTags @(1,2) -rolePermissions @("Microsoft.Intune_PolicySets_Read", "Microsoft.Intune_EndpointAnalytics_Read") -AsJson
    Generates a new Role definition object with report only permissions presets, plus additional access, in json format

    .OUTPUTS
    PSObject. New-IDMRoleDefinition returns Definition object by default
    Json. New-IDMRoleDefinition returns json format of definition if -AsJson specified

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0
    #>

    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Application-Manager','Help-Desk-Operator','Read-Only-Operator','Report-Only','Endpoint-Security-Manager')]
        [string]$PermissionSet,

        [Parameter(Mandatory=$false)]
        [string[]]$RolePermissions,

        [Parameter(Mandatory=$false)]
        [string[]]$ScopeTags,

        [Parameter(Mandatory=$false)]
        [switch]$AsJson
    )

    $Actions = @()

    Switch($PermissionSet){
        'Application-Manager' {
            $Actions = @(
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_MobileApps_Create",
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_MobileApps_Update",
                "Microsoft.Intune_MobileApps_Delete",
                "Microsoft.Intune_MobileApps_Assign",
                "Microsoft.Intune_MobileApps_Relate",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedApps_Create",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedApps_Update",
                "Microsoft.Intune_ManagedApps_Delete",
                "Microsoft.Intune_ManagedApps_Assign",
                "Microsoft.Intune_ManagedApps_Wipe",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_AndroidSync_UpdateApps",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_PolicySets_Assign",
                "Microsoft.Intune_PolicySets_Create",
                "Microsoft.Intune_PolicySets_Delete",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_PolicySets_Update",
                "Microsoft.Intune_AssignmentFilter_Create",
                "Microsoft.Intune_AssignmentFilter_Delete",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_AssignmentFilter_Update",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )
        }

        'Help-Desk-Operator' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_MobileApps_Assign",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedApps_Assign",
                "Microsoft.Intune_ManagedApps_Wipe",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_Update",
                "Microsoft.Intune_ManagedDevices_SetPrimaryUser",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_RemoteTasks_Wipe",
                "Microsoft.Intune_RemoteTasks_Retire",
                "Microsoft.Intune_RemoteTasks_RemoteLock",
                "Microsoft.Intune_RemoteTasks_ResetPasscode",
                "Microsoft.Intune_RemoteTasks_EnableLostMode",
                "Microsoft.Intune_RemoteTasks_DisableLostMode",
                "Microsoft.Intune_RemoteTasks_LocateDevice",
                "Microsoft.Intune_RemoteTasks_PlayLostModeSound",
                "Microsoft.Intune_RemoteTasks_SetDeviceName",
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_RemoteTasks_ShutDown",
                "Microsoft.Intune_RemoteTasks_RequestRemoteAssistance",
                "Microsoft.Intune_RemoteTasks_EnableWindowsIntuneAgent",
                "Microsoft.Intune_RemoteTasks_CleanPC",
                "Microsoft.Intune_RemoteTasks_ManageSharedDeviceUsers",
                "Microsoft.Intune_RemoteTasks_SyncDevice",
                "Microsoft.Intune_RemoteTasks_WindowsDefender",
                "Microsoft.Intune_RemoteTasks_RotateBitLockerKeys",
                "Microsoft.Intune_RemoteTasks_UpdateDeviceAccount",
                "Microsoft.Intune_RemoteTasks_RevokeAppleVppLicenses",
                "Microsoft.Intune_RemoteTasks_CustomNotification",
                "Microsoft.Intune_RemoteTasks_ActivateDeviceEsim",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistanceApp_ViewScreen",
                "Microsoft.Intune_RemoteAssistanceApp_TakeFullControl",
                "Microsoft.Intune_RemoteAssistanceApp_Elevation",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_RemoteTasks_RotateFileVaultKey",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_RemoteTasks_ConfigurationManagerAction",
                "Microsoft.Intune_RemoteTasks_DeviceLogs",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )

        }

        'Read-Only-Operator' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_Reports_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_Customization_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read"
            )

        }

        'Report-Only' {
            $Actions = @(
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_MobileApps_ViewReports"
            )
        }

        'Endpoint-Security-Manager' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedDevices_Delete",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_Update",
                "Microsoft.Intune_ManagedDevices_SetPrimaryUser",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Create",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Update",
                "Microsoft.Intune_DeviceCompliancePolices_Delete",
                "Microsoft.Intune_DeviceCompliancePolices_Assign",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_Reports_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_ConfigurationManagerAction",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_RemoteTasks_RemoteLock",
                "Microsoft.Intune_RemoteTasks_RotateBitLockerKeys",
                "Microsoft.Intune_RemoteTasks_RotateFileVaultKey",
                "Microsoft.Intune_RemoteTasks_ShutDown",
                "Microsoft.Intune_RemoteTasks_SyncDevice",
                "Microsoft.Intune_RemoteTasks_WindowsDefender",
                "Microsoft.Intune_SecurityBaselines_Create",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_SecurityBaselines_Update",
                "Microsoft.Intune_SecurityBaselines_Delete",
                "Microsoft.Intune_SecurityBaselines_Assign",
                "Microsoft.Intune_SecurityTasks_Read",
                "Microsoft.Intune_SecurityTasks_Update",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )
        }
    }

    #append any additional permission sets to action list
    If($rolePermissions){
        $Actions += $rolePermissions | Select -Unique
    }

    #added default if not scopes have been specified
    If(-Not($ScopeTags)){
        $ScopeTags += 0
    }

    #build roles permissions object
    #v1.0 $rolesProperties = "" | Select '@odata.type',displayName,description,roleScopeTagIds,permissions,isBuiltInRoleDefinition
    $rolesProperties = "" | Select '@odata.type',displayName,description,roleScopeTagIds,permissions,rolePermissions,isBuiltInRoleDefinition,isBuiltIn
    $rolesProperties.'@odata.type' = '#microsoft.graph.roleDefinition'
    $rolesProperties.displayName = $DisplayName
    If($Description){$rolesProperties.description = $Description}

    If($ScopeTags.count -gt 0){$rolesProperties.roleScopeTagIds = $ScopeTags}
    #Build custom object for actions
    #v1.0 $actionsProperties = "" | Select actions
    $actionsProperties = "" | Select "@odata.type",actions,resourceActions
    $actionsProperties."@odata.type" = "microsoft.graph.rolePermission"
    $actionsProperties.actions = $Actions

    #build resourceActions object
    $resourceProperties = "" | Select "@odata.type",allowedResourceActions,notAllowedResourceActions
    $resourceProperties."@odata.type" = "microsoft.graph.resourceAction"
    $resourceProperties.allowedResourceActions = $Actions
    $resourceProperties.notAllowedResourceActions = @()
    #$resourceProperties
    #append to roles
    $actionsProperties.resourceActions = @($resourceProperties)

    #append actions to permissions as object within an array @()
    $rolesProperties.permissions = @($actionsProperties)
    $rolesProperties.rolePermissions = @($actionsProperties)

    #Added builtin role definition
    $rolesProperties.isBuiltInRoleDefinition = $false
    #beta
    $rolesProperties.isBuiltIn = $false
    #convert to json
    #$rolesProperties
    $data = $rolesProperties
    If($AsJson){
        $data = ConvertTo-json $rolesProperties -Depth 10
    }

    return $data
}