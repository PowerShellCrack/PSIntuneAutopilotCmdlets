


#region
Function Get-IDMAzureUser{

    <#
    .SYNOPSIS
        This function is used to get AAD Users from the Graph API REST interface

    .DESCRIPTION
        The function connects to the Graph API Interface and gets any users registered with AAD

    .PARAMETER Id
        Must be in GUID format. This is the users GUID

    .PARAMETER UPN
        Must be in UPN format (email). This is the user principal name (eg user@domain.com)

    .PARAMETER Property
        Option to filter user based on property.

    .PARAMETER AuthToken
        Defaults to $Global:AuthToken
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .EXAMPLE
        Get-IDMAzureUser -Id '12981fe3-6049-4039-853f-e20c8d327116'
        Returns specific user by GUID registered with Azure AD

    .EXAMPLE
        Get-IDMAzureUser -userPrincipleName user@domain.com
        Returns specific user by UserPrincipalName registered with Azure AD

    .LINK
    https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
    #>

    [CmdletBinding(DefaultParameterSetName='ID')]
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,ParameterSetName='ID')]
        [string]$Id,

        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,ParameterSetName='UPN')]
        [Alias('User','EMail')]
        [System.Net.Mail.MailAddress]$UPN,

        [Parameter(Mandatory=$false)]
        [ValidateSet('id','userPrincipalName','surname','officeLocation','mail','displayName','givenName')]
        [String]$Property
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
        $User_resource = "users"
    }
    Process{
        If ($PSCmdlet.ParameterSetName -eq "ID"){
            $QueryBy = $Id
        }
        If ($PSCmdlet.ParameterSetName -eq "UPN"){
            $QueryBy = $UPN
        }
        try {
            if([string]::IsNullOrEmpty($QueryBy))
            {
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
                Write-Verbose $uri
                $Response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
            }
            else {
                if([string]::IsNullOrEmpty($Property)){
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$QueryBy"
                    Write-Verbose $uri
                    $Response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
                }
                else {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$QueryBy/$Property"
                    Write-Verbose $uri
                    $Response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
                }
            }
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        return $response
    }
}


Function Get-IDMAzureUsers{
    <#
    .SYNOPSIS
        This function is used to get a users in Azure

    .DESCRIPTION
        The function connects to the Graph API Interface and gets users

    .PARAMETER Filter
    Filters by User by looking for characters that are equal to its filterby parameter

    .PARAMETER FilterBy
    Options are: UserPrincipalName,SurName,EMailAddress,SearchDisplayName. Defaults to 'UserPrincipalName'

    .PARAMETER IncludeGuests
    [True | False] Include users that have an external label on them

    .PARAMETER AuthToken
        Defaults to $Global:AuthToken
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .EXAMPLE
        Get-IDMAzureUsers
        Returns all users except guest

    .EXAMPLE
        Get-IDMAzureUsers -IncludeGuests
        Returns all users except guest

    .EXAMPLE
        Get-IDMAzureUsers -Filter 'AdeleV@dtolab.ltd'
        Returns a user with UPN of 'AdeleV@dtolab.ltd'

    .EXAMPLE
        @('John','Bob') | Get-IDMAzureUsers -FilterBy SearchDisplayName
        Returns all users with display name of Bob of John in it

    .LINK
        https://docs.microsoft.com/en-us/graph/api/user-list?view=graph-rest-beta&tabs=http
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [ValidateSet('UserPrincipalName','SurName','EMailAddress','SearchDisplayName')]
        [string]$FilterBy = 'UserPrincipalName',

        [switch]$IncludeGuests
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "users"

        If($FilterBy -eq 'SearchDisplayName' -and -NOT($AuthToken['ConsistencyLevel'])){
            $AuthToken += @{ConsistencyLevel = 'eventual'}
        }
        $filterQuery=$null
    }
    Process{
        $Query = @()

        If($PSBoundParameters.ContainsKey('Filter')){
            switch($FilterBy){
               'UserPrincipalName' {$Query += "userPrincipalName eq '$Filter'";$Operator='filter'}
               'SurName' {$Query += "SurName eq '$Filter'";$Operator='filter'}
               'EMailAddress' {$Query += "mail eq '$Filter'";$Operator='filter'}
               'SearchDisplayName' {$Query += "`"displayName:$Filter`"";$Operator='search'}
           }
        }

        #build query filter if exists
        If($Query.count -ge 1){
            $filterQuery = "`?`$$Operator=" + ($Query -join ' and ')
        }
        If($IncludeGuests){
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource" + $filterQuery
        }Else{
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=userType eq 'Member'" + $filterQuery
        }

        try {
            Write-Verbose "Get $uri"
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        return $response.value
    }
}


Function Get-IDMDeviceAssignedUser{
    <#
    .SYNOPSIS
        This function is used to get a Managed Device username from the Graph API REST interface

    .DESCRIPTION
        The function connects to the Graph API Interface and gets a managed device users registered with Intune MDM

    .PARAMETER DeviceID
        Must be in GUID format. This is for Intune Managed device ID, not the Azure ID or Object ID

    .PARAMETER AuthToken
        Defaults to $Global:AuthToken
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .EXAMPLE
        Get-IDMDeviceAssignedUser -DeviceID 0a212b6a-e1d2-4985-b9dd-4cf5205662fa
        Returns a managed device user registered in Intune

    .EXAMPLE
        @('0a212b6a-e1d2-4985-b9dd-4cf5205662fa','ef07dabc-2b16-48cb-9692-a6ab9ff48c55') | Get-IDMDeviceAssignedUser
        Returns a device pending action that matches DeviceID's
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        $DeviceID
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
    }
    Process{
        $Resource = "deviceManagement/manageddevices('$DeviceID')?`$select=userId"

        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Write-Verbose "Get $uri"
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        return $response.userId
    }
}


function Set-IDMDeviceAssignedUser {

    <#
    .SYNOPSIS
        This updates the Intune device primary user

    .DESCRIPTION
        This updates the Intune device primary user

    .PARAMETER DeviceId
        Must be in GUID format. This is for Intune Managed device ID, not the Azure ID or Object ID

    .PARAMETER UserId
        Must be in GUID format. This is for Azure User ID

    .PARAMETER UPN
        Must be in UPN format (email). This is the user principal name (eg user@domain.com)

    .PARAMETER AuthToken
        Defaults to $Global:AuthToken
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .EXAMPLE
        Set-IDMDeviceAssignedUser -DeviceID '08d06b3b-8513-417b-80ee-9dc8a3beb377' -UPN 'AdeleV@dtolab.ltd'
        Assigns the user to device'

    .EXAMPLE
        Set-IDMDeviceAssignedUser -DeviceID '08d06b3b-8513-417b-80ee-9dc8a3beb377' -UserId 'c9d00ac2-b07d-4477-961b-442bbc424586'
        Assigns the user to device'

    .EXAMPLE
        @('08d06b3b-8513-417b-80ee-9dc8a3beb377','c9d00ac2-b07d-4477-961b-442bbc424586') | Set-IDMDeviceAssignedUser -UPN 'AdeleV@dtolab.ltd'
        Returns all users with display name of Bob of John in it

    .LINK
    Get-IDMAzureUser
    #>

    [CmdletBinding(DefaultParameterSetName='ID')]
    param
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        $DeviceId,

        [Parameter(Mandatory=$True,ParameterSetName='ID')]
        [string]$UserId,

        [Parameter(Mandatory=$True,ParameterSetName='UPN')]
        [Alias('User','EMail')]
        [System.Net.Mail.MailAddress]$UPN
    )
    Begin{
        $graphApiVersion = "beta"
        If ($PSCmdlet.ParameterSetName -eq "UPN"){
            $UserId = (Get-IDMAzureUser -UPN $UPN).Id
        }
    }
    Process{
        $Resource = "deviceManagement/managedDevices('$DeviceId')/users/`$ref"

        #build UserUri body; convert to JSON
        $userUri = "https://graph.microsoft.com/$graphApiVersion/users/" + $UserId
        $JSON = @{ "@odata.id"="$userUri" } | ConvertTo-Json -Compress

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        try {
            Write-Verbose "Get $uri"
            $null = Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ErrorAction Stop
        } catch {
            Write-ErrorResponse($_)
        }
    }

}
#incase scripts are using old alias
New-Alias -Name "Get-IDMDeviceAADUser" -Value Get-IDMAzureUser -ErrorAction SilentlyContinue -Force
