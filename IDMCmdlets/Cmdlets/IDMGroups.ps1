
Function Get-IDMAzureGroup{
    <#
    .SYNOPSIS
    This function is used to get Azure Groups from the Graph API REST interface for Intune

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with Azure

    .PARAMETER GroupName
    The name of the group to get

    .PARAMETER id
    The id of the group to get

    .PARAMETER Members
    Get the members of the group

    .EXAMPLE
    Get-IDMAzureGroup
    Returns all users registered with Azure Entra

    .EXAMPLE
    Get-IDMAzureGroup -GroupName 'SG-AZ-ORG-ALL-Users'
    Returns the group with the name 'SG-AZ-ORG-ALL-Users'

    .EXAMPLE
    Get-IDMAzureGroup -id '12345678-1234-1234-1234-123456789012'
    Returns the group with the id '12345678-1234-1234-1234-123456789012'

    .EXAMPLE
    Get-IDMAzureGroup -Members
    Returns all members of all groups

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-beta&tabs=http
    #>
    [cmdletbinding()]
    param
    (
        [string]$GroupName,
        [string]$id,
        [switch]$Members
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "groups"

    $ShowAll = $True
    if($id){
        $Property = 'id'
        $Value = $id
        $FilterString = "?`$filter=id eq '$id'"
        $ShowAll = $False
    }

    if($GroupName){
        $Property = 'displayname'
        $Value = $GroupName
        $FilterString = "?`$filter=displayname eq '$GroupName'"
        $ShowAll = $False
    }

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)$FilterString"
        $Result = Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop

        # if group or id is not found or null, by default, all groups are displayed
        #ensure all groups are not displayed when id or groupname params are used
        If($ShowAll -eq $False -and $Result.value.$Property -ne $Value){
            $Result = $Null
        }

        If($Members)
        {
            Foreach($Group in $Result.value){
                $GID = $Group.id
                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($GroupResource)/$GID/Members"
                (Invoke-MgGraphRequest -Method Get -Uri $uri -ErrorAction Stop).Value
            }
        }
        Else{
            $Result.value
        }
    }
    Catch{
        Write-ErrorResponse($_)
    }
}




Function New-IDMAzureGroup{
    <#
    .SYNOPSIS
    This function is used create Azure Entra group

    .DESCRIPTION
    The function connects to the Graph API Interface and creates an Azure Entra group

    .PARAMETER DisplayName
    The name of the group to create

    .PARAMETER Description
    The description of the group to create

    .PARAMETER RuleExpression
    The rule expression of the group to create

    .EXAMPLE
    New-IDMAzureGroup -DisplayName 'SG-AZ-ORG-ALL-Users' -Description 'All Users in the Organization'
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .EXAMPLE
    New-IDMAzureGroup -DisplayName 'SG-AZ-DYN-ORG-ALL-VirtualMachines' -Description 'All Virtual Machines in the Organization' -RuleExpression '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform")'
    Creates a dynamic group that includes all Virtual Machines in the Organization

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http
    #>
    #
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$False)]
        [string]$RuleExpression,

        [ValidateSet('Unified','DynamicMembership')]
        [string]$GroupType = 'DynamicMembership'
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "groups"

    If($GroupType -eq 'DynamicMembership' -and [string]::IsNullOrEmpty($RuleExpression) ){
        Write-Error "You must supply '-RuleExpressions' parameter when GroupType equals 'DynamicMembership'!"
        Break
    }

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    If($Description){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description}
    $object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @($GroupType)
    $object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false
    If($Description){
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','')
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','').replace('-','')
    }
    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    If($GroupType -eq 'DynamicMembership'){
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $RuleExpression
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
    }
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

Function New-IDMAzureDynamicGroup{
    <#
    .SYNOPSIS
    This function is used create Azure Entra dynamic group

    .DESCRIPTION
    The function connects to the Graph API Interface and creates an Azure Entra group

    .PARAMETER DisplayName
    The name of the group to create

    .PARAMETER Description
    The description of the group to create

    .PARAMETER RuleExpression
    The rule expression of the group to create

    .EXAMPLE
    New-IDMAzureDynamicGroup -DisplayName 'SG-AZ-DYN-ORG-ALL-VirtualMachines' -Description 'All Virtual Machines in the Organization' -RuleExpression '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform")'
    Creates a dynamic group that includes all Virtual Machines in the Organization

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$true)]
        [string]$RuleExpression
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "groups"

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
    $object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false
    $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','')
    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $RuleExpression
    $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
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



Function Update-IDMAzureDynamicGroup{
    <#
    .SYNOPSIS
    This function is used update a Azure Entra dynamic group

    .DESCRIPTION
    The function connects to the Graph API Interface and updates an Azure Entra dynamic group

    .PARAMETER DisplayName
    The name of the group to update

    .PARAMETER Id
    The Id of the group to update

    .PARAMETER NewName
    The new name of the group

    .PARAMETER NewDescription
    The new description of the group

    .PARAMETER NewRuleExpression
    The new rule expression of the group

    .EXAMPLE
    Update-IDMAzureDynamicGroup -DisplayName 'SG-AZ-DYN-ORG-ALL-VirtualMachines' -NewRuleExpression '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform")'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0&tabs=http

    .LINK
    Get-IDMAzureGroup
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [string]$Id,

        [string]$NewName,

        [Parameter(Mandatory=$false)]
        [string]$NewDescription,

        [Parameter(Mandatory=$false)]
        [string]$NewRuleExpression
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "groups"

    If($PsCmdlet.ParameterSetName -eq 'Name'){
        $ExistingGroup = Get-IDMAzureGroup -GroupName $DisplayName
    }

    If($PsCmdlet.ParameterSetName -eq 'Id'){
        $ExistingGroup = Get-IDMAzureGroup -Id $Id
    }

    If( [string]::IsNullOrEmpty($NewName) -and [string]::IsNullOrEmpty($NewDescription) -and [string]::IsNullOrEmpty($NewRuleExpression) ){
        Write-Verbose "No changes made the group. Please specify an update parameter -NewName, -NewDescription, or -NewRuleExpressison"
        Break
    }

    If($NewRuleExpression){
        If($ExistingGroup.membershipRule -eq $NewRuleExpression){
            Write-Verbose "MembershipRule are the same. No changes made the group"
            Break
        }
    }

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    If($NewName){
        $object | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $NewName
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $NewName.replace(' ','')
    }
    If($NewDescription){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $NewDescription}
    #$object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
    #$object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false

    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    If($NewRuleExpression){
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $NewRuleExpression
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
    }
    $JSON = $object | ConvertTo-Json

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$($ExistingGroup.Id)"
        $null = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body $JSON -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Remove-IDMAzureGroup{
    <#
    .SYNOPSIS
    This function is used to remove an Azure Entra group

    .PARAMETER GroupName
    The name of the group to remove

    .DESCRIPTION
    The function connects to the Graph API Interface and removes an Azure Entra group

    .EXAMPLE
    Remove-IDMAzureGroup -GroupName 'SG-AZ-DYN-ORG-ALL-VirtualMachines'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-delete?view=graph-rest-1.0&tabs=http

    .LINK
    Get-IDMAzureGroup
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "groups"

    $AzureGroupId = (Get-IDMAzureGroup -GroupName $GroupName).id

    If($AzureGroupId)
    {
        Write-verbose ("Azure Entra Group [{0}] has an Id of [{1}]" -f $GroupName,$AzureGroupId)
    }
    Else{
        Write-verbose ("No Azure Entra Group by the name of [{0}] was found" -f $GroupName)
        Break
    }

    try {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)/$AzureGroupId"
        Invoke-MgGraphRequest -Uri $uri -Method Delete
    }
    catch {
        Write-ErrorResponse($_)
    }
}
