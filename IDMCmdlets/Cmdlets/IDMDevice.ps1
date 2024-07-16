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

    .PARAMETER All
    [True | False] Excluded by default. Included all devices managed by Intune

    .PARAMETER ExcludeMDM
    [True | False] Excludes and device managed by Mdm. Cannot be combined with All

    .PARAMETER Expand
    [True | False] Gets Azure device object and merges with Intune results. If results are larger than 1000; issue may arise.

    .EXAMPLE
    Get-IDMDevice -Filter DTOLAB
    Returns all managed devices that has the characters DTOLAB in it.

    .EXAMPLE
    Get-IDMDevice
    Returns all managed devices but excludes EAS devices registered within the Intune Service

    .EXAMPLE
    Get-IDMDevice -All
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
        [Alias('IncludeEAS')]
        [switch]$All,

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeMDM,

        [Parameter(Mandatory=$false)]
        [switch]$Expand,

        [Parameter(Mandatory=$false)]
        [hashtable]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $filterQuery=$null

    if($All.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }

    if($Count_Params -gt 1){
        write-warning "Multiple parameters set, specify a single parameter -All, -ExcludeMDM or no parameter against the function"
        break
    }

    $OrQuery = @()
    $AndQuery = @()

    If($All){
        #include all queries by leaving filter empty
    }
    Elseif($ExcludeMDM){
        $OrQuery += "managementAgent eq 'configurationManagerClientEas'"
        $OrQuery += "managementAgent eq 'easIntuneClient'"
        $OrQuery += "managementAgent eq 'eas'"
    }
    Else{
        $OrQuery += "managementAgent eq 'configurationManagerClientMdm'"
        $OrQuery += "managementAgent eq 'configurationManagerClient'"
        $OrQuery += "managementAgent eq 'intuneClient'"
        $OrQuery += "managementAgent eq 'mdm'"
        $OrQuery += "managementAgent eq 'easMdm'"
    }

    If($PSBoundParameters.ContainsKey('Filter')){
        #TEST $Filter = '46VEYL1'
        $AndQuery += "contains(deviceName,'$($Filter)')"
    }

    #TEST $Platform = 'Windows'
    If($PSBoundParameters.ContainsKey('Platform')){
        $AndQuery += "operatingSystem eq '$($Platform)'"
    }

    #append ?$filter once, then apply orquery and andquery
    If($OrQuery -or $AndQuery){
        $filterQuery = @('?$filter=')
        If($OrQuery.count -ge 1){
            $filterQuery += "(" + ($OrQuery -join ' or ') + ")"
        }
        If($filterQuery.count -ge 2 -and $AndQuery.count -ge 1){
            $filterQuery += ' and '
        }
        If($AndQuery.count -ge 1){
            $filterQuery += "(" + ($AndQuery -join ' and ') + ")"
        }
        $filterQuery = $filterQuery -join ''
    }Else{
        $filterQuery = $null
    }

    $allPages = @()

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery
    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $graphData = (Invoke-MgGraphRequest -Method Get -Uri $uri)
    }
    catch {
        New-Exception -Exception $_.Exception
    }
    #add the first page of results to the array
    $allPages += $graphData.value

    #if there is a nextLink property, then there are more pages of results
    if ($graphData.'@odata.nextLink') {

        try {

            #loop through the pages of results until there is no nextLink property
            do {

                $graphData = (Invoke-MgGraphRequest -Uri $graphData.'@odata.nextLink')
                $allPages += $graphData.value

            } until (
                !$graphData.'@odata.nextLink'
            )

        }
        catch {
            New-Exception -Exception $_.Exception
        }
    }
    #return the array of results
    $graphData = $allPages


    If($Expand)
    {
        $Devices = @()
        $AzureDeviceParam = @{}
        #Populate AAD devices using splat for filter and platform to minimize seach field
        # this is becuse if results are more than gropah will show, the results coudl be skewed.

        If($PSBoundParameters.ContainsKey('Filter')){
            $AzureDeviceParam += @{Filter = $Filter}
        }
        If($PSBoundParameters.ContainsKey('Platform')){
            $AzureDeviceParam += @{Platform = $Platform}
        }

        $IntuneDeviceObjects = ConvertFrom-GraphHashtable -GraphData $graphData.value -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource"

        #Call another Azure cmdlet
        #Write-Verbose ($AzureDeviceParam.GetEnumerator() | Format-List | Out-String)
        $AADObjects = Get-IDMAzureDevices @AzureDeviceParam

        #TEST $IntuneItem = $IntuneDeviceObjects | Where {$_.deviceName -eq 'DTOLAB-WKHV002'}
        Foreach($IntuneItem in $IntuneDeviceObjects)
        {
            $OutputItem = New-Object PSObject
            $OutputItem = $IntuneItem
            #first add all properties of Intune device
            <#
            Foreach($p in $IntuneItem.psobject.properties.name){
                $OutputItem | Add-Member NoteProperty $p.name -Value $IntuneItem.($p)
            }
            #>
            #TEST $LinkedAzureDevice = $AADObjects | Where displayName -eq 'DTOLAB-WKHV002'
            If($LinkedAzureDevice = $AADObjects | Where deviceId -eq $IntuneItem.azureADDeviceId){

                Foreach($p in $LinkedAzureDevice.psobject.properties.name){
                    switch($p){
                        'id' {$OutputItem | Add-Member NoteProperty "azureADObjectId" -Value $LinkedAzureDevice.($p) -Force}
                        'deviceVersion' {}
                        'deviceMetadata' {}
                        'alternativeSecurityIds' {}
                        default {$OutputItem | Add-Member NoteProperty $p -Value $LinkedAzureDevice.($p) -Force}
                    }
                }
                # Add the object to our array of output objects
            }

            $Devices += $OutputItem
        }
    }
    Else{
        $Devices = $graphData
    }

    If($Passthru -or $Expand){
        return $Devices
    }Else{
        return (ConvertFrom-GraphHashtable -GraphData $Devices -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
    }
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

    .PARAMETER All
    [True | False] Excluded by default. Included all devices

    .PARAMETER ExcludeMDM
    [True | False] Excludes and device managed by Mdm. Cannot be combined with All

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
    Get-IDMDevice -All
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
        [Alias('IncludeEAS')]
        [switch]$All,

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeMDM,

        [Parameter(Mandatory=$false)]
        [switch]$Expand,

        [switch]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $filterQuery=$null

    if($All.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }

    if($Count_Params -gt 1){
        write-warning "Multiple parameters set, specify a single parameter -All, -ExcludeMDM or no parameter against the function"
        break
    }

    $OrQuery = @()
    $AndQuery = @()

    If($All){
        #include all queries by leaving filter empty
    }
    Elseif($ExcludeMDM){
        $OrQuery += "managementAgent eq 'configurationManagerClientEas'"
        $OrQuery += "managementAgent eq 'easIntuneClient'"
        $OrQuery += "managementAgent eq 'eas'"
    }
    Else{
        $OrQuery += "managementAgent eq 'configurationManagerClientMdm'"
        $OrQuery += "managementAgent eq 'configurationManagerClient'"
        $OrQuery += "managementAgent eq 'intuneClient'"
        $OrQuery += "managementAgent eq 'mdm'"
        $OrQuery += "managementAgent eq 'easMdm'"
    }

    If($PSBoundParameters.ContainsKey('Filter')){
        #TEST $Filter = '46VEYL1'
        $AndQuery += "contains(deviceName,'$($Filter)')"
    }

    #TEST $Platform = 'Windows'
    If($PSBoundParameters.ContainsKey('Platform')){
        $AndQuery += "operatingSystem eq '$($Platform)'"
    }

    #append ?$filter once, then apply orquery and andquery
    If($OrQuery -or $AndQuery){
        $filterQuery = @('?$filter=')
        If($OrQuery.count -ge 1){
            $filterQuery += "(" + ($OrQuery -join ' or ') + ")"
        }
        If($filterQuery.count -ge 2 -and $AndQuery.count -ge 1){
            $filterQuery += ' and '
        }
        If($AndQuery.count -ge 1){
            $filterQuery += "(" + ($AndQuery -join ' and ') + ")"
        }
        $filterQuery = $filterQuery -join ''
    }Else{
        $filterQuery = $null
    }

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery

    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
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

        #TEST $Item = $Response.Value | Where deviceName -eq 'DTOLAB-WKHV002'
        Foreach($Item in $Response.Value)
        {
            $AzureDevicesUris += "$Global:GraphEndpoint/$graphApiVersion/devices?`$filter=displayName eq '$($Item.deviceName)'"
        }
        #invoke a query on all
        $AzureDevices = $AzureDevicesUris | Invoke-IDMGraphBatchRequests -Verbose:$VerbosePreference

        #TEST $Item = $Response.Value | Where deviceName -eq 'DTOLAB-WKHV002'
        Foreach($Item in $Response.Value)
        {
            $OutputItem = New-Object PSObject
            #first add all properties of Intune device
            
            Foreach($p in $Item.psobject.properties.name){
                $OutputItem | Add-Member NoteProperty $p -Value $Item.($p)
            }
            
            #TEST $LinkedAzureDevice = $AADObjects | Where displayName -eq 'DTOLAB-WKHV002'
            If($LinkedAzureDevice = $AzureDevices | Where deviceId -eq $Item.azureADDeviceId){

                Foreach($p in $LinkedAzureDevice.psobject.properties.name){
                    switch($p){
                        'id' {$OutputItem | Add-Member NoteProperty "azureADObjectId" -Value $LinkedAzureDevice.($p) -Force}
                        'deviceVersion' {}
                        'deviceMetadata' {}
                        'alternativeSecurityIds' {}
                        default {$OutputItem | Add-Member NoteProperty $p -Value $LinkedAzureDevice.($p) -Force}
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
        # Defining graph variables
        $graphApiVersion = "beta"
        $Resource = "devices"
        $RequestParams = @{}

        If( ($FilterBy -eq 'SearchDisplayName') ){
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
                'StartWithDisplayName' {$Query += "startswith(displayName,'$Filter')";$Operator='filter'}
                'NOTStartWithDisplayName' {$Query += "NOT startsWith(displayName,'$Filter')";$Operator='filter'}
                'SearchDisplayName' {$Query += "`"displayName:$Filter`"";$Operator='search'}
                default {$Operator='filter'}
            }
        }

        #build query filter if exists
        If($Query.count -ge 1){
            $filterQuery = "`?`$$Operator=" + ($Query -join ' and ')
        }

        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource" + $filterQuery

        try {
            Write-Verbose ("Invoking GET API: {0}" -f $uri)
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
            return (ConvertFrom-GraphHashtable -GraphData $Response.Value -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
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
        # Defining graph variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/managedDevices"
    }
    Process{
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$DeviceID"

        try {    
            Write-Verbose ("Invoking GET API: {0}" -f $uri)
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
    End{
        $DeviceState = (ConvertFrom-GraphHashtable -GraphData $Response).deviceActionResults

        If($AllActions){
            return $DeviceState.deviceActionResults
        }Else{
            return ($DeviceState.deviceActionResults | Where actionState -eq 'pending')
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
    param([switch]$Passthru)

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCategories"

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"

    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }

    If($Passthru){
        return $response.value
    }else {
        return (ConvertFrom-GraphHashtable -GraphData $Response.Value -ResourceUri $uri)
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

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $Categories = Get-IDMDeviceCategory
    $CategoryId = ($Categories | Where displayName -eq $Category).id

    #$requestBody = @{ "@odata.id" = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceCategories/3137f37d-ff7c-48ec-af57-d4404faf844e" }
    $requestBody = @{ "@odata.id" = "$Global:GraphEndpoint/$graphApiVersion/deviceManagement/deviceCategories/$CategoryId" }
    $BodyJson = $requestBody | ConvertTo-Json

    #$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/08d06b3b-8513-417b-80ee-9dc8a3beb377/deviceCategory/`$ref"
    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$DeviceID/deviceCategory/`$ref"

    try {
        Write-Verbose ("Invoking PUT API: {0}" -f $uri)
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

        $RequestParams = @{}
    }
    Process{

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
                Write-Verbose ("Invoking {0} API:  {1}" -f $RequestParams.Method,$RequestParams.uri)
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



Function Get-IDMStaleDevices{

    <#
    .SYNOPSIS
        This function is used to get Intune Managed Devices from the Graph API REST interface
    .DESCRIPTION
        The function connects to the Graph API Interface and gets any Intune Managed Device that has not synced with the service in the past X days
    .EXAMPLE
        Get-IDMStaleDevices
        Returns all managed devices but excludes EAS devices registered within the Intune Service that have not checked in for X days
    .NOTES
        https://docs.microsoft.com/en-us/azure/active-directory/devices/manage-stale-devices
    #>

    [cmdletbinding()]
    param
    (
        [Int]$cutoffDays,
        [switch]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    # this will get the date/time at the time this is run, so if it is 3pm on 2/27, the 90 day back mark would be 11/29 at 3pm, meaning if a device checked in on 11/29 at 3:01pm it would not meet the check
    #change cutoffDays to negative number if non-negative was supplied
    if($cutoffDays -ge 0){
        $cutoffDays = -$cutoffDays
    }
    $cutoffDate = (Get-Date).AddDays($cutoffDays).ToString("yyyy-MM-dd")

    $uri = ("$global:GraphEndpoint/$graphApiVersion/$($Resource)?`$filter=managementAgent eq 'mdm' or managementAgent eq 'easMDM' and lastSyncDateTime le $cutoffDate")

    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $devices = (Invoke-MgGraphRequest -Uri $uri -Method Get).Value
    }catch {
        Write-ErrorResponse($_.Exception)
    }

    If($Passthru){
        return $devices
    }Else{
        return (ConvertFrom-GraphHashtable -GraphData $devices -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
    }
}

Function Get-IDMStaleAzureDevices{

    <#
    .SYNOPSIS
    This function is used to get Intune Managed Devices from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Managed Device that has not synced with the service in the past X days
    .EXAMPLE
    Get-IDMStaleAzureDevices
    Returns all managed devices but excludes EAS devices registered within the Intune Service that have not checked in for X days
    .NOTES
    https://docs.microsoft.com/en-us/azure/active-directory/devices/manage-stale-devices
    #>

    [cmdletbinding()]
    param
    (
        [Int]$cutoffDays,
        [switch]$Passthru
    )
    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "devices"

    # this will get the date/time at the time this is run, so if it is 3pm on 2/27, the 90 day back mark would be 11/29 at 3pm, meaning if a device checked in on 11/29 at 3:01pm it would not meet the check
    #change cutoffDays to negative number if non-negative was supplied
    if($cutoffDays -ge 0){
        $cutoffDays = -$cutoffDays
    }else{
        $cutoffDays = -60
    }
    $cutoffDate = (Get-Date).AddDays($cutoffDays)

    #$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=approximateLastSignInDateTime le $cutoffDate"
    $uri = "$global:GraphEndpoint/$graphApiVersion/$($Resource)"

    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $devices = (Invoke-MgGraphRequest -Uri $uri -Method Get).Value | Where {($_.ApproximateLastLogonTimeStamp -le $cutoffDate) -and ($_.AccountEnabled -eq $false)}
    }catch {
        Write-ErrorResponse($_.Exception)
    }

    If($Passthru){
        return $devices
    }Else{
        return (ConvertFrom-GraphHashtable -GraphData $devices -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
    }
}

function Remove-IDMStaleDevices{

    <#
    .SYNOPSIS
    This function retires all stale devices in Intune that have not checked in within 90 days
    .DESCRIPTION
    The function connects to the Graph API Interface and retires any Intune Managed Device that has not synced with the service in the past 90 days
    .EXAMPLE
    Remove-IDMStaleDevices -Devices $deviceList
    Executes a retire command against all devices in the list provided and then deletes the record from the console
    .NOTES
    NAME: Remove-IDMStaleDevices
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $DeviceID
    )
    $graphApiVersion = "beta"
    try {
        $Resource = "deviceManagement/managedDevices/$DeviceID/retire"
        $uri = "$global:GraphEndpoint/$graphApiVersion/$($resource)"
        Write-Output "Sending retire command to $DeviceID"
        Invoke-MgGraphRequest -Uri $uri -Method Post -UseBasicParsing

        $Resource = "deviceManagement/managedDevices('$DeviceID')"
        $uri = "$global:GraphEndpoint/$graphApiVersion/$($resource)"
        Write-Output "Sending delete command to $DeviceID"

        Write-Verbose ("Invoking DELETE API: {0}" -f $uri)
        Invoke-MgGraphRequest -Uri $uri -Method Delete -UseBasicParsing
    }catch {
        Write-ErrorResponse($_.Exception)
    }
}



Function Get-IDMAzureDeviceExtension {
    <#
    https://docs.microsoft.com/en-us/graph/api/resources/extensionproperty?view=graph-rest-1.0
    https://docs.microsoft.com/en-us/graph/extensibility-overview
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DeviceID,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1,15)]
        [int]$ExtensionID
    )
    $graphApiVersion = "beta"
    $Resource = "devices"


    $uri = "$global:GraphEndpoint/$graphApiVersion/$($Resource)/$($DeviceID)?`$select=extensionAttributes"
    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $response = Invoke-MgGraphRequest -Uri $uri -Method Get
    }catch {
        Write-ErrorResponse($_.Exception)
    }

    $DeviceExtensions = (ConvertFrom-GraphHashtable -GraphData $Response.extensionAttributes -ResourceUri $uri).extensionAttributes

    If($ExtensionID){
        Return $DeviceExtensions | Select -ExpandProperty "extensionAttribute$($ExtensionID)"
    }Else{
        Return $DeviceExtensions
    }

}



Function Set-IDMAzureDeviceExtension {
    <#
    https://docs.microsoft.com/en-us/graph/api/resources/extensionproperty?view=graph-rest-1.0
    https://docs.microsoft.com/en-us/graph/extensibility-overview
    https://docs.microsoft.com/en-us/graph/api/application-post-extensionproperty?view=graph-rest-beta&tabs=http
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DeviceID,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1,15)]
        [int]$ExtensionID,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$ExtensionValue
    )
    $graphApiVersion = "beta"
    $Resource = "devices"

    If($ExtensionValue.Length -gt 0){
        $JsonBody = @{"extensionAttributes" = @{"extensionAttribute$($ExtensionID)" = $ExtensionValue}} | ConvertTo-Json
    }Else{
        $JsonBody = @{"extensionAttributes" = @{"extensionAttribute$($ExtensionID)" = $null}} | ConvertTo-Json
    }

    $uri = "$global:GraphEndpoint/$graphApiVersion/$($Resource)/$($DeviceID)"

    try {
        Write-Verbose ("Invoking PATCH API: {0}" -f $uri)
        $null = Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JsonBody
    }
    catch {
        Write-ErrorResponse($_.Exception)
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

    .PARAMETER TargetId
        Must be in guid format. Should be id of device or id of user

    .PARAMETER TargetSet
        Must be in hashtable format. Should contain an id of device and/or id of user
        eg. @{devices='b215decf-4188-4d19-9e22-fb2e89ae0fec';users='c9d00ac2-b07d-4477-961b-442bbc424586'}

    .EXAMPLE
    $targetSet = @{devices=$syncHash.Data.SelectedDevice.azureADObjectId;users=$syncHash.Data.AssignedUser.id}
    $platform = $syncHash.Data.SelectedDevice.OperatingSystem

    Get-IDMIntuneAssignments -TargetSet $targetSet -Platform $platform -IncludePolicySetInherits

    .EXAMPLE
    $targetSet = @{devices=$syncHash.AssignmentWindow.DeviceData.azureADObjectId;users=$syncHash.AssignmentWindow.UserData.id}
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
        $UriResources += "$Global:GraphEndpoint/$graphApiVersion/$($Target.ToLower())/$TargetId/memberOf"
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
                    'deviceManagement/groupPolicyConfigurations'
                    'deviceManagement/windowsAutopilotDeploymentProfiles'
                    'deviceManagement/deviceCompliancePolicies'
                    'deviceManagement/deviceComplianceScripts'
                    'deviceManagement/deviceConfigurations'
                    'deviceManagement/configurationPolicies'
                    'deviceManagement/deviceEnrollmentConfigurations'
                    'deviceManagement/deviceHealthScripts'
                    'deviceManagement/deviceManagementScripts'
                    'deviceManagement/roleScopeTags'
                    'deviceManagement/windowsDriverUpdateProfiles'
                    'deviceManagement/windowsQualityUpdateProfiles'
                    'deviceManagement/windowsFeatureUpdateProfiles'
                    'deviceAppManagement/windowsInformationProtectionPolicies'
                    'deviceAppManagement/mdmWindowsInformationProtectionPolicies'
                    'deviceAppManagement/policysets'
                    'deviceAppManagement/intents'
                    'deviceAppManagement/targetedManagedAppConfigurations'
                    'deviceAppManagement/managedAppPolicies'
                    'deviceAppManagement/mobileAppConfigurations'
                    'deviceAppManagement/mobileApps'
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
    #$GraphRequests = $UriResources | Invoke-IDMGraphRequests

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
    
    #$ResourceAssignments = $PlatformResources | %{ $_.uri + '/' + $_.id + '/assignments'} |
    $ResourceAssignments = $PlatformResources | %{ $_.uri + '/assignments'} |
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
