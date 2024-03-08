Function Get-IDMDevice{

    <#
    .SYNOPSIS
    This function is used to get Intune Managed Devices from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Managed Device

    .PARAMETER Platform
    Options are: Windows,Android,MacOS,iOS. SRetrieves only devices with that Operating system

    .PARAMETER Filter
    Filters by devicename by looking for characters that are CONTAINED in name. This means it can either be exact of part of the name

    .PARAMETER IncludeEAS
    [True | False] Excluded by default. Included device managed by Active sync

    .PARAMETER ExcludeMDM
    [True | False] Excludes and device managed by Mdm. Cannot be combined with IncludeEAS

    .PARAMETER Expand
    [True | False] Gets Azure device object and merges with Intune results. If results are larger than 1000; issue may arise.

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
    Get-IDMDevice -Filter DTOLAB
    Returns all managed devices that has the characters DTOLAB in it.

    .EXAMPLE
    Get-IDMDevice
    Returns all managed devices but excludes EAS devices registered within the Intune Service

    .EXAMPLE
    Get-IDMDevice -IncludeEAS
    Returns all managed devices including EAS devices registered within the Intune Service

    .EXAMPLE
    Get-IDMDevice -Expand
   Retrieves Intune Managed Devices and association with Azure AD

    .LINK
    Get-IDMAzureDevices
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateSet('Windows','Android','MacOS','iOS')]
        [string]$Platform,

        [Parameter(Mandatory=$false)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeEAS,

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeMDM,

        [Parameter(Mandatory=$false)]
        [switch]$Expand
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $filterQuery=$null

    if($IncludeEAS.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }

    if($Count_Params -gt 1){
        write-warning "Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
        break
    }

    $Query = @()
    if($IncludeEAS){
        #include all queries by leaving filter empty
    }
    Elseif($ExcludeMDM){
        $Query += "managementAgent eq 'eas'"
        $Query += "managementAgent eq 'easIntuneClient'"
        $Query += "managementAgent eq 'configurationManagerClientEas'"
    }
    Else{
        $Query += "managementAgent eq 'mdm'"
        $Query += "managementAgent eq 'easMdm'"
        $Query += "managementAgent eq 'intuneClient'"
        $Query += "managementAgent eq 'configurationManagerClient'"
        $Query += "managementAgent eq 'configurationManagerClientMdm'"
    }

    If($PSBoundParameters.ContainsKey('Filter')){
        #TEST $Filter = '46VEYL1'
        $Query += "contains(deviceName,'$($Filter)')"
    }

    If($PSBoundParameters.ContainsKey('Platform')){
        $Query += "operatingSystem eq '$($Platform)'"
    }

    #build query filter if exists
    If($Query.count -ge 1){
        $filterQuery = "`?`$filter=" + ($Query -join ' and ')
    }

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery

    try {
        Write-Verbose "Get $uri"
        $Response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }

    If($Expand)
    {
        $Devices = @()
        #Populate AAD devices using splat for filter and platform to minimize seach field
        # this is becuse if results are more than gropah will show, the results coudl be skewed.

        If($PSBoundParameters.ContainsKey('Filter')){
            $AzureDeviceParam += @{Filter = $Filter}
        }
        If($PSBoundParameters.ContainsKey('Platform')){
            $AzureDeviceParam += @{Platform = $Platform}
        }

        #Call another Azure cmdlet
        #Write-Verbose ($AzureDeviceParam.GetEnumerator() | Format-List | Out-String)
        $AADObjects = Get-IDMAzureDevices @AzureDeviceParam

        #TEST $Item = $Response.Value | Where deviceName -eq 'DTOLAB-46VEYL1'
        Foreach($Item in $Response.Value)
        {
            $OutputItem = New-Object PSObject
            #first add all properties of Intune device
            Foreach($p in $Item | Get-Member -MemberType NoteProperty){
                $OutputItem | Add-Member NoteProperty $p.name -Value $Item.($p.name)
            }

            #TEST $LinkedIntuneDevice = $AADObjects | Where displayName -eq 'DTOLAB-46VEYL1'
            If($LinkedIntuneDevice = $AADObjects | Where deviceId -eq $Item.azureADDeviceId){

                Foreach($p in $LinkedIntuneDevice | Get-Member -MemberType NoteProperty){
                    switch($p.name){
                        'id' {$OutputItem | Add-Member NoteProperty "azureADObjectId" -Value $LinkedIntuneDevice.($p.name) -Force}
                        'deviceVersion' {<#For internal use only.#>}
                        'deviceMetadata' {<#For internal use only.#>}
                        'alternativeSecurityIds' {<#For internal use only.#>}
                        default {$OutputItem | Add-Member NoteProperty $p.name -Value $LinkedIntuneDevice.($p.name) -Force}
                    }
                }
                # Add the object to our array of output objects
            }

            $Devices += $OutputItem
        }
    }
    Else{
        $Devices = $Response.Value
    }

    return $Devices
}

Function Get-IDMDevices{

    <#
    .SYNOPSIS
    This function is in BETA; used to get Intune Managed Devices from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Managed Device

    .PARAMETER Platform
    Options are: Windows,Android,MacOS,iOS. SRetrieves only devices with that Operating system

    .PARAMETER Filter
    Filters by devicename by looking for characters that are CONTAINED in name. This means it can either be exact of part of the name

    .PARAMETER IncludeEAS
    [True | False] Excluded by default. Included device managed by Active sync

    .PARAMETER ExcludeMDM
    [True | False] Excludes and device managed by Mdm. Cannot be combined with IncludeEAS

    .PARAMETER Expand
    [True | False] Gets Azure device object and merges with Intune results. This will query each individual device use multithread query
    However this can take a while if results are large.

    .PARAMETER Passthru
    [True | False] if graph result is larger than 1000, -Passthru passes next link data with devices. If Passthru is not used, default output is devices

    .EXAMPLE
    Get-IDMDevice -Filter DTOLAB
    Returns all managed devices that has the characters DTOLAB in it.

    .EXAMPLE
    Get-IDMDevice
    Returns all managed devices but excludes EAS devices registered within the Intune Service

    .EXAMPLE
    Get-IDMDevice -IncludeEAS
    Returns all managed devices including EAS devices registered within the Intune Service

    .EXAMPLE
    Get-IDMDevice -Expand
    Retrieves Intune Managed Devices and association with Azure AD

    .LINK
    Get-IDMAzureDevices
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateSet('Windows','Android','MacOS','iOS')]
        [string]$Platform,

        [Parameter(Mandatory=$false)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeEAS,

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeMDM,

        [Parameter(Mandatory=$false)]
        [switch]$Expand,

        [switch]$Passthru
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $filterQuery=$null

    if($IncludeEAS.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }

    if($Count_Params -gt 1){
        write-warning "Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
        break
    }

    $Query = @()
    if($IncludeEAS){
        #include all queries by leaving filter empty
    }
    Elseif($ExcludeMDM){
        $Query += "managementAgent eq 'eas'"
        $Query += "managementAgent eq 'easIntuneClient'"
        $Query += "managementAgent eq 'configurationManagerClientEas'"
    }
    Else{
        $Query += "managementAgent eq 'mdm'"
        $Query += "managementAgent eq 'easMdm'"
        $Query += "managementAgent eq 'intuneClient'"
        $Query += "managementAgent eq 'configurationManagerClient'"
        $Query += "managementAgent eq 'configurationManagerClientMdm'"
    }

    If($PSBoundParameters.ContainsKey('Filter')){
        #TEST $Filter = '46VEYL1'
        $Query += "contains(deviceName,'$($Filter)')"
    }

    If($PSBoundParameters.ContainsKey('Platform')){
        $Query += "operatingSystem eq '$($Platform)'"
    }

    #build query filter if exists
    If($Query.count -ge 1){
        $filterQuery = "`?`$filter=" + ($Query -join ' and ')
    }

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery

    try {
        Write-Verbose "Get $uri"
        $Response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }

    If($Expand)
    {
        $AzureDevicesUris = @()
        $Devices = @()
        #Populate AAD devices using splat for filter and platform to minimize seach field
        # this is becuse if results are more than gropah will show, the results coudl be skewed.

        #TEST $Item = $Response.Value | Where deviceName -eq 'DTOLAB-46VEYL1'
        Foreach($Item in $Response.Value)
        {
            $AzureDevicesUris += "$Global:GraphEndpoint/$graphApiVersion/devices?`$filter=displayName eq '$($Item.deviceName)'"
        }
        #invoke a query on all
        $AzureDevices = $AzureDevicesUris | Invoke-IDMGraphBatchRequests -Verbose:$VerbosePreference

        #TEST $Item = $Response.Value | Where deviceName -eq 'DTOLAB-46VEYL1'
        Foreach($Item in $Response.Value)
        {
            $OutputItem = New-Object PSObject
            #first add all properties of Intune device
            Foreach($p in $Item | Get-Member -MemberType NoteProperty){
                $OutputItem | Add-Member NoteProperty $p.name -Value $Item.($p.name)
            }

            #TEST $LinkedIntuneDevice = $AADObjects | Where displayName -eq 'DTOLAB-46VEYL1'
            If($LinkedIntuneDevice = $AzureDevices | Where deviceId -eq $Item.azureADDeviceId){

                Foreach($p in $LinkedIntuneDevice | Get-Member -MemberType NoteProperty){
                    switch($p.name){
                        'id' {$OutputItem | Add-Member NoteProperty "azureADObjectId" -Value $LinkedIntuneDevice.($p.name) -Force}
                        'deviceVersion' {<#For internal use only.#>}
                        'deviceMetadata' {<#For internal use only.#>}
                        'alternativeSecurityIds' {<#For internal use only.#>}
                        default {$OutputItem | Add-Member NoteProperty $p.name -Value $LinkedIntuneDevice.($p.name) -Force}
                    }
                }
                # Add the object to our array of output objects
            }

            $Devices += $OutputItem
        }
    }
    Else{
        $Devices = $Response.Value
    }

    #Build a object with next link
    $NextLinkAndDevices = "" | Select NextLink,Devices
    $NextLinkAndDevices.NextLink = $Response.'@odata.nextLink'
    $NextLinkAndDevices.Devices = $Devices

    If($Passthru){
        return $NextLinkAndDevices
    }Else{
        return $Devices
    }
}


Function Get-IDMAzureDevices{
<#
    .SYNOPSIS
    This function is used to get Azure Devices from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Azure Device

    .PARAMETER Filter
    Filters by devicename by looking for characters that are CONTAINED in name. This means it can either be exact of part of the name

    .PARAMETER FilterBy
    Options are: DisplayName,StartWithDisplayName,NOTStartWithDisplayName. Defaults to 'StartWithDisplayName'

    .PARAMETER Platform
    Options are: Windows,Android,MacOS,iOS. SRetrieves only devices with that Operating system

    .PARAMETER Passthru
    [True | False] -Passthru passes graph raw data. If Passthru is not used, default output is devices

    .EXAMPLE
    Get-IDMAzureDevices -Filter DTOLAB
   Returns all Azure devices that has the characters DTOLAB in it.

    .EXAMPLE
    @('WVD1,'WVD2') | Get-IDMAzureDevices -FilterBy SearchDisplayName
    Returns Azure devices with WVD1 and WVD2 in device name

    .LINK
    https://docs.microsoft.com/en-us/graph/api/device-list?view=graph-rest-beta&tabs=http
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [ValidateSet('DisplayName','StartWithDisplayName','NOTStartWithDisplayName','SearchDisplayName')]
        [string]$FilterBy = 'StartWithDisplayName',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Windows','Android','MacOS','iOS')]
        [string]$Platform,

        [switch]$Passthru
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "devices"
        $RequestParams = @{}

        If( ($FilterBy -eq 'SearchDisplayName') -and -NOT($AuthToken['ConsistencyLevel'])){
            $RequestParams += @{"Headers" = @{ConsistencyLevel = 'eventual'}}
        }
        $filterQuery=$null
    }
    Process{
        $Query = @()

        If($PSBoundParameters.ContainsKey('Platform')){
            $Query += "operatingSystem eq '$($Platform)'"
        }

        If($PSBoundParameters.ContainsKey('Filter')){
             switch($FilterBy){
                'DisplayName' {$Query += "displayName eq '$Filter'";$Operator='filter'}
                'StartWithDisplayName' {$Query += "startswith(displayName, '$Filter')";$Operator='filter'}
                'NOTStartWithDisplayName' {$Query += "NOT startsWith(displayName, '$Filter')";$Operator='filter'}
                'SearchDisplayName' {$Query += "`"displayName:$Filter`"";$Operator='search'}
            }
        }

        #build query filter if exists
        If($Query.count -ge 1){
            $filterQuery = "`?`$$Operator=" + ($Query -join ' and ')
        }

        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery

        try {
            Write-Verbose "Get $uri"
            $Response = Invoke-MgGraphRequest -Uri $uri @RequestParams -Method Get -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        If($Passthru){
            return $Response
        }Else{
            return $Response.Value
        }
    }
}


Function Get-IDMDevicePendingActions{
    <#
    .SYNOPSIS
        This function is used to get a Managed Device pending Actions

    .DESCRIPTION
        The function connects to the Graph API Interface and gets a managed device pending actions

    .PARAMETER AllActions
        [True | False] Allows all actions, if even completed, to display.

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
        Get-IDMDevicePendingActions -DeviceID 08d06b3b-8513-417b-80ee-9dc8a3beb377
        Returns a device pending action that matches DeviceID

    .EXAMPLE
        @('0a212b6a-e1d2-4985-b9dd-4cf5205662fa','ef07dabc-2b16-48cb-9692-a6ab9ff48c55') | Get-IDMDevicePendingActions
        Returns a device pending action that matches DeviceID's
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        $DeviceID,

        [Parameter(Mandatory=$false)]
        [switch]$AllActions
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
    }
    Process{
        $Resource = "deviceManagement/manageddevices/$DeviceID"

        try {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)"
            Write-Verbose "Get $uri"
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        If($AllActions){
            return $response.deviceActionResults
        }Else{
            return ($response.deviceActionResults | Where actionState -eq 'pending')
        }

    }
}



Function Get-IDMDeviceCategory{
    <#
    .SYNOPSIS
    Gets Device Category details.

    .DESCRIPTION
    The Get-IDMDeviceCategory cmdlet returns either a list of all categories for the current Azure AD tenant, or information for the specific profile specified by its ID.

   .EXAMPLE
    Get a list of all Device Categories.

    Get-IDMDeviceCategory
    #>
    [cmdletbinding()]
    param()

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCategories"

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"

    try {
        Write-Verbose "GET $uri"
        $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }
    Finally{
        $response.Value
    }
}


Function Set-IDMDeviceCategory{
    <#
    .SYNOPSIS
    Sets Device Category

    .DESCRIPTION
    The Set-IDMDeviceCategory cmdlet sets the category of device ID

    .EXAMPLE
    Set-IDMDeviceCategory -DeviceID '08d06b3b-8513-417b-80ee-9dc8a3beb377' -Category 'Standard Device'

    .LINK
    Get-IDMDeviceCategory

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $DeviceID,

        [Parameter(Mandatory=$true)]
        $Category
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $Categories = Get-IDMDeviceCategory -AuthToken $AuthToken
    $CategoryId = ($Categories | Where displayName -eq $Category).id

    #$requestBody = @{ "@odata.id" = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceCategories/3137f37d-ff7c-48ec-af57-d4404faf844e" }
    $requestBody = @{ "@odata.id" = "$Global:GraphEndpoint/$graphApiVersion/deviceManagement/deviceCategories/$CategoryId" }
    $BodyJson = $requestBody | ConvertTo-Json

    #$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/08d06b3b-8513-417b-80ee-9dc8a3beb377/deviceCategory/`$ref"
    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$DeviceID/deviceCategory/`$ref"

    try {
        Write-Verbose "GET $uri"
        $null = Invoke-MgGraphRequest -Uri $uri -Body $BodyJson -Method PUT -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }
}


Function Invoke-IDMDeviceAction{
    <#
    .SYNOPSIS
    This function is used to initiate a intune device action from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and sets a generic Intune Resource
    .EXAMPLE
    Invoke-IDMDeviceAction -DeviceID $DeviceID -remoteLock
    Resets a managed device passcode
    .NOTES
    NAME: Invoke-IDMDeviceAction
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,HelpMessage="DeviceId (guid) for the Device you want to take action on must be specified:")]
        $DeviceID,

        [Parameter(Mandatory=$true)]
        [ValidateSet('RemoteLock','ResetPasscode','Wipe','Retire','Delete','Sync','Rename')]
        $Action,

        [switch]$Force,

        $NewDeviceName
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }
        $graphApiVersion = "Beta"
    }
    Process{
        $RequestParams = @{
            Headers=$AuthToken
        }

        switch($Action){

            'RemoteLock'
            {
                $WhatIfMsg = "Performing the operation `"Reset passcode`" on target `"$DeviceID`"."
                $ActionMsg = "Sending remoteLock command to device ID: $DeviceID..."

                $Resource = "deviceManagement/managedDevices/$DeviceID/remoteLock"
                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                }
            }

            'ResetPasscode'
            {
                $WhatIfMsg = "Performing the operation `"Reset passcode`" on target `"$DeviceID`"."
                $ActionMsg = "Resetting the Passcode for device ID: $DeviceID..."

                $Resource = "deviceManagement/managedDevices/$DeviceID/resetPasscode"
                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                }
            }

            'Wipe'
            {
                $WhatIfMsg = "Performing the operation `"Device Wipe`" on target `"$DeviceID`"."
                $ActionMsg = "Sending [Wipe] action to device ID: `"$DeviceID`"..."

                $Resource = "deviceManagement/managedDevices/$DeviceID/wipe"
                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                }
            }

            'Retire'
            {
                $WhatIfMsg = "Performing the operation `"Retire Device`" on target `"$DeviceID`"."

                $ActionMsg = "Sending [Retire] to device ID: `"$DeviceID`"..."
                $Resource = "deviceManagement/managedDevices/$DeviceID/retire"

                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                }

            }

            'Delete'
            {
                $WhatIfMsg = "Performing the operation `"Delete Device`" on target `"$DeviceID`"."

                $ActionMsg = "Deleting `"$DeviceID`"..."
                $Resource = "deviceManagement/managedDevices('$DeviceID')"

                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Delete'
                }
            }

            'Sync'
            {
                $WhatIfMsg = "Performing the operation `"Device Sync`" on target `"$DeviceID`"."
                $ActionMsg = "Syncing device Id: `"$DeviceID`"..."
                $Resource = "deviceManagement/managedDevices('$DeviceID')/syncDevice"

                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                }

            }

            'Rename'
            {
                $WhatIfMsg = "Performing the operation `"Device Rename`" on target `"$DeviceID`"."
                $ActionMsg = "Sending rename action to device Id: `"$DeviceID`" as new name: `"$NewDeviceName`"..."
                If($Null -eq $NewDeviceName){Break}

                $JSON = @"
                {
                    deviceName:"$($NewDeviceName)"
                }
"@
                $Resource = "deviceManagement/managedDevices('$DeviceID')/setDeviceName"

                $uri = "$Global:GraphEndpoint/$graphApiVersion/$($resource)"

                $RequestParams += @{
                    Uri=$uri
                    Method='Post'
                    Body=$Json
                    ContentType="application/json"
                }
            }
        }

        If($WhatIfPreference){
            Write-Host "What if: $WhatIfMsg"
        }
        else {
            Write-host $ActionMsg
            try {
                Write-Verbose ("{0}: {1}" -f $RequestParams.Method,$RequestParams.uri)
                $null = Invoke-MgGraphRequest @RequestParams -ErrorAction Stop
            }
            catch {
                Write-ErrorResponse($_)
            }
        }
    }
}


Function Remove-IDMDeviceRecords{

    [CmdletBinding(DefaultParameterSetName='All')]
    Param
    (
        [Parameter(ParameterSetName='All',Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [Parameter(ParameterSetName='Individual',Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [Parameter(ParameterSetName='Azure',Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [Parameter(ParameterSetName='ConfigMgr',Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        $ComputerName,

        [Parameter(ParameterSetName='All')]
        [Parameter(ParameterSetName='Azure')]
        [Parameter(ParameterSetName='ConfigMgr')]
        [switch]$All,

        [Parameter(ParameterSetName='Individual')]
        [switch]$AD,

        [Parameter(ParameterSetName='Individual')]
        [Parameter(ParameterSetName='Azure')]
        [switch]$AAD,

        [Parameter(ParameterSetName='Individual')]
        [Parameter(ParameterSetName='Azure')]
        [switch]$Intune,

        [Parameter(ParameterSetName='Individual')]
        [Parameter(ParameterSetName='Azure')]
        [switch]$Autopilot,

        [Parameter(ParameterSetName='Individual')]
        [Parameter(ParameterSetName='ConfigMgr')]
        [switch]$ConfigMgr,

        [Parameter(ParameterSetName='Individual')]
        [Parameter(Mandatory=$true,ParameterSetName='ConfigMgr')]
        [Parameter(Mandatory=$true,ParameterSetName='All')]
        [switch]$SiteCode
    )

    # Delete from AD
    If ($PSBoundParameters.ContainsKey("AD") -or $PSBoundParameters.ContainsKey("All"))
    {
        Try
        {
            Write-host "Retrieving Active Directory computer account..." -NoNewline
            $Searcher = [ADSISearcher]::new()
            $Searcher.Filter = "(sAMAccountName=$ComputerName`$)"
            [void]$Searcher.PropertiesToLoad.Add("distinguishedName")
            $ComputerAccount = $Searcher.FindOne()
            If ($ComputerAccount)
            {
                Write-host "Success" -ForegroundColor Green
                Write-Host "   Deleting computer account…" -NoNewline
                $DirectoryEntry = $ComputerAccount.GetDirectoryEntry()
                $Result = $DirectoryEntry.DeleteTree()
                Write-Host "Success" -ForegroundColor Green
            }
            Else
            {
                Write-host "Not found!" -ForegroundColor Red
            }
        }
        Catch
        {
            Write-Host ("Failed to remove {0} from AD! {1}" -f $ComputerName,$_.Exception.Message) -ForegroundColor Red
        }
    }

    # Delete from Azure AD
    If ($PSBoundParameters.ContainsKey("AAD") -or $PSBoundParameters.ContainsKey("All"))
    {
        Try
        {
            Write-host "Retrieving Azure AD device records..." -NoNewline
            [array]$AzureADDevices = Get-IDMAzureDevices -Filter $ComputerName -ErrorAction Stop
            If ($AzureADDevices.Count -ge 1)
            {
                Write-Host "Success" -ForegroundColor Green
                Foreach ($AzureADDevice in $AzureADDevices)
                {
                    Write-host "   Deleting DisplayName: $($AzureADDevice.DisplayName)  |  ObjectId: $($AzureADDevice.ObjectId)  |  DeviceId: $($AzureADDevice.DeviceId) …" -NoNewline
                    Remove-IDMAzureDevices -ObjectId $AzureADDevice.ObjectId -ErrorAction Stop
                    Write-host "Success" -ForegroundColor Green
                }
            }
            Else
            {
                Write-host "Not found!" -ForegroundColor Red
            }
        }
        Catch
        {
            Write-Host ("Failed to remove {0} from Azure AD! {1}" -f $ComputerName,$_.Exception.Message) -ForegroundColor Red
        }
    }

    # Delete from Intune
    If ($PSBoundParameters.ContainsKey("Intune") -or $PSBoundParameters.ContainsKey("Autopilot") -or $PSBoundParameters.ContainsKey("All"))
    {
        Try
        {
            Write-host "Retrieving Intune managed device records..." -NoNewline
            [array]$IntuneDevices = Get-IDMDevice -Filter $ComputerName -ErrorAction Stop
            If ($IntuneDevices.Count -ge 1)
            {
                Write-Host "Success" -ForegroundColor Green
                If ($PSBoundParameters.ContainsKey("Intune") -or $PSBoundParameters.ContainsKey("All"))
                {
                    foreach ($IntuneDevice in $IntuneDevices)
                    {
                        Write-host "   Deleting DeviceName: $($IntuneDevice.deviceName)  |  Id: $($IntuneDevice.Id)  |  AzureADDeviceId: $($IntuneDevice.azureADDeviceId)  |  SerialNumber: $($IntuneDevice.serialNumber) …" -NoNewline
                        Invoke-IDMDeviceAction -DeviceID $IntuneDevice.Id -Action Delete -ErrorAction Stop
                        Write-host "Success" -ForegroundColor Green
                    }
                }
            }
            Else
            {
                Write-host "Not found!" -ForegroundColor Red
            }
        }
        Catch
        {
            Write-Host ("Failed to remove {0} from Intune! {1}" -f $ComputerName,$_.Exception.Message) -ForegroundColor Red
        }
    }

    # Delete Autopilot device
    If ($PSBoundParameters.ContainsKey("Autopilot") -or $PSBoundParameters.ContainsKey("All"))
    {
        If ($IntuneDevices.Count -ge 1)
        {
            Try
            {
                Write-host "Retrieving Autopilot device registration..." -NoNewline
                $AutopilotDevices = New-Object System.Collections.ArrayList
                foreach ($IntuneDevice in $IntuneDevices)
                {
                    $URI = "$Global:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($IntuneDevice.serialNumber)')"
                    $AutopilotDevice = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
                    [void]$AutopilotDevices.Add($AutopilotDevice)
                }
                Write-Host "Success" -ForegroundColor Green

                foreach ($device in $AutopilotDevices)
                {
                    Write-host "   Deleting SerialNumber: $($Device.value.serialNumber)  |  Model: $($Device.value.model)  |  Id: $($Device.value.id)  |  GroupTag: $($Device.value.groupTag)  |  ManagedDeviceId: $($device.value.managedDeviceId) …" -NoNewline
                    $URI = "$Global:GraphEndpoint/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($device.value.Id)"
                    $AutopilotDevice = Invoke-MgGraphRequest -Uri $uri -Method Delete -ErrorAction Stop
                    Write-Host "Success" -ForegroundColor Green
                }
            }
            Catch
            {
                Write-Host ("Failed to remove {0} from Autopilot Devices! {1}" -f $ComputerName,$_.Exception.Message) -ForegroundColor Red
            }
        }
    }

    # Delete from ConfigMgr
    If ($PSBoundParameters.ContainsKey("ConfigMgr") -or $PSBoundParameters.ContainsKey("All"))
    {
        Try
        {
            Write-host "Retrieving ConfigMgr device records..." -NoNewline
            $SiteCode = (Get-PSDrive -PSProvider $SiteCode -ErrorAction Stop).Name
            Set-Location ("$SiteCode" + ":") -ErrorAction Stop
            [array]$ConfigMgrDevices = Get-CMDevice -Name $ComputerName -Fast -ErrorAction Stop
            Write-Host "Success" -ForegroundColor Green
            foreach ($ConfigMgrDevice in $ConfigMgrDevices)
            {
                Write-host "   Deleting Name: $($ConfigMgrDevice.Name)  |  ResourceID: $($ConfigMgrDevice.ResourceID)  |  SMSID: $($ConfigMgrDevice.SMSID)  |  UserDomainName: $($ConfigMgrDevice.UserDomainName) …" -NoNewline
                Remove-CMDevice -InputObject $ConfigMgrDevice -Force -ErrorAction Stop
                Write-Host "Success" -ForegroundColor Green
            }
        }
        Catch
        {
            Write-Host ("Failed to remove {0} from Configuration Manager! {1}" -f $ComputerName,$_.Exception.Message) -ForegroundColor Red
        }
    }

}



Function Get-IDMIntuneAssignments{
    <#
    .SYNOPSIS
    This function is used to retrieve all assignments from Intune for both device and users

    .DESCRIPTION
    The function connects to the Graph API Interface and retrieves all assignments from Intune for both device and users

    .PARAMETER Target
        [Devices | Users]. Specify which assignment to pull.

    .PARAMETER Target
        [Device | User]. Specify which assignment to pull. Target id is associated

    .PARAMETER TargetId
        Must be in guid format. SHould be id of device or id of user

    .PARAMETER TargetSet
        Must be in hashtable format. Should contain an id of device and/or id of user
        eg. @{devices='b215decf-4188-4d19-9e22-fb2e89ae0fec';users='c9d00ac2-b07d-4477-961b-442bbc424586'}

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
    $targetSet = @{devices=$syncHash.Data.SelectedDevice.azureADObjectId;users=$syncHash.Data.AssignedUser.id}
    $platform = $syncHash.Data.SelectedDevice.OperatingSystem

    Get-IDMIntuneAssignments -TargetSet $targetSet -Platform $platform -AuthToken $syncHash.Data.AuthToken -IncludePolicySetInherits
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='TargetArea')]
        [ValidateSet('Devices','Users')]
        [string]$Target,

        [Parameter(Mandatory=$true,ParameterSetName='TargetArea')]
        [string]$TargetId,

        [Parameter(Mandatory=$true,ParameterSetName='TargetSet')]
        [hashtable]$TargetSet,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Windows','Android','MacOS','iOS')]
        [string]$Platform = 'Windows',

        [Parameter(Mandatory=$false)]
        [switch]$IncludePolicySetInherits

    )

    $graphApiVersion = "beta"

    #First get all Azure AD groups this device is a member of.
    $UriResources = @()
    #TEST $TargetSet = @{devices=$syncHash.Data.SelectedDevice.azureADObjectId;users=$syncHash.Data.AssignedUser.id}
    If($TargetSet)
    {
        $UriResources += $TargetSet.GetEnumerator() | %{"$Global:GraphEndpoint/$graphApiVersion/$($_.Name)/$($_.Value)/memberOf"}
    }
    Else{
        $UriResources += "$Global:GraphEndpoint/$graphApiVersion/$($Target.ToLower())/memberOf"
    }

    #loop through each Intune Component, then get assignments for each
    Switch($Platform){
        'Windows' {
                $PlatformType = @('microsoftStore',
                                'win32LobApp',
                                'windows',
                                'officeSuiteApp',
                                'sharedPC',
                                'editionUpgrade',
                                'webApp'
                )

                $PlatformComponents = @(
                    #'deviceManagement/advancedThreatProtectionOnboardingStateSummary'
                    'deviceManagement/windowsAutopilotDeploymentProfiles'
                    'deviceManagement/deviceCompliancePolicies'
                    'deviceManagement/deviceComplianceScripts'
                    'deviceManagement/deviceConfigurations'
                    'deviceManagement/configurationPolicies'
                    'deviceManagement/deviceEnrollmentConfigurations'
                    'deviceManagement/deviceHealthScripts'
                    'deviceManagement/deviceManagementScripts'
                    'deviceManagement/roleScopeTags'
                    #'deviceManagement/windowsDriverUpdateProfiles'
                    'deviceManagement/windowsQualityUpdateProfiles'
                    'deviceManagement/windowsFeatureUpdateProfiles'
                    'deviceAppManagement/windowsInformationProtectionPolicies'
                    'deviceAppManagement/mdmWindowsInformationProtectionPolicies'
                    'deviceAppManagement/mobileApps'
                    'deviceAppManagement/policysets'
                    #'deviceAppManagement/assignmentFilters'
                )
        }

        'Android' {$PlatformType = @('android',
                                    'webApp',
                                    'aosp'
                                    )
                $PlatformComponents = @(
                    'deviceManagement/androidDeviceOwnerEnrollmentProfiles'
                    'deviceAppManagement/androidForWorkAppConfigurationSchemas'
                    'deviceAppManagement/androidForWorkEnrollmentProfiles'
                    'deviceAppManagement/androidForWorkSettings'
                    'deviceAppManagement/androidManagedStoreAccountEnterpriseSettings'
                    'deviceAppManagement/androidManagedStoreAppConfigurationSchemas'
                )
    }

        'MacOS'   {$PlatformType = @('ios',
                                    'macOS',
                                    'webApp'
                                    )
                $PlatformComponents = @(

                )
        }

        'iOS'     {$PlatformType = @('ios',
                                    'webApp'
                                    )
                $PlatformComponents = @(

                )
        }
    }

    #Add component URIs
    $UriResources += $PlatformComponents | %{ "$Global:GraphEndpoint/$graphApiVersion/$($_)"}
    Foreach($Uri in $UriResources){
        Write-Verbose "URI: $Uri"
    }

    #BATCH CALL #1: Do a batch call on device,users and platform resources to get all properties
    #Using -Passthru with Invoke-IDMGraphRequests will out graph data including next link and context.
    #No Passthru will out value only
    #$GraphRequests = $UriResources | Invoke-IDMGraphRequests -Threads $UriResources.Count
    $GraphRequests = $UriResources | Invoke-IDMGraphBatchRequests -Verbose:$VerbosePreference
    #$GraphRequests = $UriResources | Invoke-IDMGraphRequests -Headers $AuthToken

    $DeviceGroups = ($GraphRequests | Where {$_.uri -like '*/devices/*/memberOf'})
    $UserGroups = ($GraphRequests | Where {$_.uri -like '*/users/*/memberOf'})

    $DeviceGroupMembers = $DeviceGroups | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }},@{N='Target';E={'Devices'}}
    $UserGroupMembers = $UserGroups | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }},@{N='Target';E={'Users'}}

    #combine device and users memberships
    $AllGroupMembers = @()
    $AllGroupMembers = $DeviceGroupMembers + $UserGroupMembers

    #NOW Build platform resources based on graph info
    $PlatformResources = ($GraphRequests | Where {$_.'@odata.type' -match ($PlatformType -join '|')}) |
                                            Select Id,uri,
                                                @{N='type';E={Set-IDMResourceFriendlyType -Category (split-path $_.uri -leaf) -ODataType $_.'@odata.type'}},
                                                @{N='name';E={Set-IDMResourceFriendlyName -Name $_.displayName -LicenseType $_.licenseType -ODataType $_.'@odata.type'}},
                                                @{N='assigned';E={If('isAssigned' -in ($_ | Get-Member -MemberType NoteProperty).Name){[boolean]$_.isAssigned}Else{'Unknown'}}}

    #BATCH CALL #2: get Assignments of all resource using batch jobs.
    #Using -Passthru with Invoke-IDMGraphRequests will out graph data including next link and context. Value contains devices. No Passthru will out value only
    #batch jobs can only be ran in series of 20; split collection up and process each group
    $ResourceAssignments = $PlatformResources | %{ $_.uri + '/' + $_.id + '/assignments'} |
                Split-IDMRequests -GroupOf 20 | ForEach-Object { $_ | Invoke-IDMGraphBatchRequests -Verbose:$VerbosePreference}
    #$ResourceAssignments = $PlatformResources | Invoke-IDMGraphRequests -Verbose:$VerbosePreference
    #$ResourceAssignments.count

    $AssignmentList= @()
    #TEST $Assignment = $ResourceAssignments[0]
    #TEST $Assignment = ($ResourceAssignments | Where Source -eq 'policySets')[0]
    $i=0
    Foreach($Assignment in $ResourceAssignments)
    {
        $ReferenceResource = $PlatformResources | Where { $Assignment.uri -eq ($_.uri + '/' + $_.id + '/assignments')}
        $AssignmentGroup = '' | Select Id,Name,Type,Mode,Target,Platform,Group,GroupType,GroupId,Assigned
        $AssignmentGroup.Id = $Assignment.id
        $AssignmentGroup.Name = $ReferenceResource.name
        $AssignmentGroup.Type = $ReferenceResource.type
        #$AssignmentGroup.Target = $Assignment.target
        $AssignmentGroup.Platform = $Platform
        $AssignmentGroup.Assigned = $ReferenceResource.assigned

        If($Assignment.intent){
            $AssignmentGroup.Mode = (Get-Culture).TextInfo.ToTitleCase($Assignment.intent)
        }Else{
            $AssignmentGroup.Mode = 'Assigned'
        }

        #Grab Policyset info
        If($Assignment.source -eq 'policySets' -and $IncludePolicySetInherits){
            $PolicySet = $True
            $PolicySetDetails = $PlatformResources | Where id -eq $Assignment.sourceId
            If(!$PolicySetDetails){
                $PolicySet = $False
            }
        }
        Else{
            $PolicySet = $False
        }

        switch($Assignment.target.'@odata.type'){
            '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                $AddToGroup = $true
                $AssignmentGroup.Group = 'All Users'
                #$ResourceAssignments += $AssignmentGroup
                $AssignmentGroup.GroupType = 'Built-In'
                $AssignmentGroup.Target = 'Users'
            }

            '#microsoft.graph.allDevicesAssignmentTarget' {
                $AddToGroup = $true
                $AssignmentGroup.Group = 'All Devices'
                $AssignmentGroup.GroupType = 'Built-In'
                $AssignmentGroup.Target = 'Devices'
            }

            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                $AssignmentGroup.Mode = 'Excluded'
                $TargetAssignments = $Assignment.target | Where '@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'
                #$Group = $TargetAssignments.GroupId[-1]
                Foreach($Group in $TargetAssignments.GroupId)
                {
                    If($Group -in $AllGroupMembers.id){
                        $GroupDetails = ($AllGroupMembers | Where id -eq $Group)
                        $AddToGroup = $true
                        $AssignmentGroup.GroupId = $GroupDetails.id
                        $AssignmentGroup.Group = $GroupDetails.displayName
                        $AssignmentGroup.GroupType = $GroupDetails.GroupType
                        $AssignmentGroup.Target = $GroupDetails.Target
                    }Else{
                        $AddToGroup = $false
                    }
                }
            }

            '#microsoft.graph.groupAssignmentTarget' {
                $TargetAssignments = $Assignment.target | Where '@odata.type' -eq '#microsoft.graph.groupAssignmentTarget'
                Foreach($Group in $TargetAssignments.GroupId)
                {
                    If($Group -in $AllGroupMembers.id){
                        $GroupDetails = ($AllGroupMembers | Where id -eq $Group)
                        $AddToGroup = $true
                        $AssignmentGroup.GroupId = $GroupDetails.id
                        $AssignmentGroup.Group = $GroupDetails.displayName
                        $AssignmentGroup.GroupType = $GroupDetails.GroupType
                        $AssignmentGroup.Target = $GroupDetails.Target
                    }Else{
                        $AddToGroup = $false
                    }
                }
            }
            default {$AddToGroup = $false}
        }#end switch

        If($AddToGroup){
            #update assignment group columns if policy is set
            If($PolicySet){
                $AssignmentGroup.Mode = 'Applied (Inherited)'
                $AssignmentGroup.Group = ($AssignmentGroup.Group + ' (' + $AssignmentGroup.GroupType + ')')
                #$AssignmentGroup.Group = ('PolicySet: ' + $PolicySet.displayName)
                #$AssignmentGroup.GroupType = ($AssignmentGroup.Group + ' (Inherited)')
                $AssignmentGroup.GroupType = ('PolicySet: ' + $PolicySetDetails.name)
            }
            $AssignmentList += $AssignmentGroup
        }
        $i++

    }#end assignment loop

    Return $AssignmentList
}
