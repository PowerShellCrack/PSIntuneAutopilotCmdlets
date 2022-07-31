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
        [switch]$Expand,

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
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

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource" + $filterQuery

    try {
        Write-Verbose "Get $uri"
        $Response = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    }

    If($Expand)
    {
        $Devices = @()
        #Populate AAD devices using splat for filter and platform to minimize seach field
        # this is becuse if results are more than gropah will show, the results coudl be skewed.

        $AzureDeviceParam = @{
            AuthToken=$AuthToken
        }
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

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken,

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

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource" + $filterQuery

    try {
        Write-Verbose "Get $uri"
        $Response = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
            $AzureDevicesUris += "https://graph.microsoft.com/$graphApiVersion/devices?`$filter=displayName eq '$($Item.deviceName)'"
        }
        #invoke a query on all
        $AzureDevices = $AzureDevicesUris | Invoke-IDMGraphRequests -Headers $AuthToken

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

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken,

        [switch]$Passthru
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "devices"

        If( ($FilterBy -eq 'SearchDisplayName') -and -NOT($AuthToken['ConsistencyLevel'])){
            $AuthToken += @{ConsistencyLevel = 'eventual'}
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

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource" + $filterQuery

        try {
            Write-Verbose "Get $uri"
            $Response = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ErrorAction Stop
        }
        catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
        [switch]$AllActions,

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
    )
    Begin{
        # Defining Variables
        $graphApiVersion = "beta"
    }
    Process{
        $Resource = "deviceManagement/manageddevices/$DeviceID"

        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Write-Verbose "Get $uri"
            $response = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ErrorAction Stop
        }
        catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
    param
    (
        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCategories"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    try {
        Write-Verbose "GET $uri"
        $response = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
        $Category,

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    $Categories = Get-IDMDeviceCategory -AuthToken $AuthToken
    $CategoryId = ($Categories | Where displayName -eq $Category).id

    #$requestBody = @{ "@odata.id" = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceCategories/3137f37d-ff7c-48ec-af57-d4404faf844e" }
    $requestBody = @{ "@odata.id" = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceCategories/$CategoryId" }
    $BodyJson = $requestBody | ConvertTo-Json

    #$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/08d06b3b-8513-417b-80ee-9dc8a3beb377/deviceCategory/`$ref"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$DeviceID/deviceCategory/`$ref"

    try {
        Write-Verbose "GET $uri"
        $null = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Body $BodyJson -Method PUT
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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

        $NewDeviceName,

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
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
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"

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
                $null = Invoke-RestMethod @RequestParams
            }
            catch {
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
        [switch]$SiteCode,

        [Parameter(Mandatory=$false,ParameterSetName='Azure')]
        $AuthToken = $Global:AuthToken
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
            [array]$AzureADDevices = Get-IDMAzureDevices -Filter $ComputerName -AuthToken $AuthToken -ErrorAction Stop
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
                    $URI = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($IntuneDevice.serialNumber)')"
                    $AutopilotDevice = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ErrorAction Stop
                    [void]$AutopilotDevices.Add($AutopilotDevice)
                }
                Write-Host "Success" -ForegroundColor Green

                foreach ($device in $AutopilotDevices)
                {
                    Write-host "   Deleting SerialNumber: $($Device.value.serialNumber)  |  Model: $($Device.value.model)  |  Id: $($Device.value.id)  |  GroupTag: $($Device.value.groupTag)  |  ManagedDeviceId: $($device.value.managedDeviceId) …" -NoNewline
                    $URI = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($device.value.Id)"
                    $AutopilotDevice = Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Delete -ErrorAction Stop
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
        [switch]$IncludePolicySetInherits,

        [Parameter(Mandatory=$false)]
        $AuthToken = $Global:AuthToken
    )

    $graphApiVersion = "beta"

    #First get all Azure AD groups this device is a member of.
    $UriResources = @()
    #TEST $TargetSet = @{devices=$syncHash.Data.SelectedDevice.azureADObjectId;users=$syncHash.Data.AssignedUser.id}
    If($TargetSet)
    {
        $UriResources += $TargetSet.GetEnumerator() | %{"https://graph.microsoft.com/$graphApiVersion/$($_.Name)/$($_.Value)/memberOf"}
    }
    Else{
        $UriResources += "https://graph.microsoft.com/$graphApiVersion/$($Target.ToLower())/memberOf"
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
                    'deviceManagement/windowsAutopilotDeploymentProfiles'
                    'deviceManagement/deviceCompliancePolicies'
                    'deviceManagement/deviceComplianceScripts'
                    'deviceManagement/deviceConfigurations'
                    'deviceManagement/deviceEnrollmentConfigurations'
                    'deviceManagement/deviceHealthScripts'
                    'deviceManagement/deviceManagementScripts'
                    'deviceManagement/roleScopeTags'
                    'deviceManagement/windowsQualityUpdateProfiles'
                    'deviceManagement/windowsFeatureUpdateProfiles'
                    'deviceAppManagement/windowsInformationProtectionPolicies'
                    'deviceAppManagement/mdmWindowsInformationProtectionPolicies'
                    'deviceAppManagement/mobileApps'
                    'deviceAppManagement/policysets'
                )
        }

        'Android' {$PlatformType = @('android',
                                    'webApp',
                                    'aosp'
                                    )
        }

        'MacOS'   {$PlatformType = @('IOS',
                                    'macOS',
                                    'webApp'
                                    )
        }

        'iOS'     {$PlatformType = @('ios',
                                    'webApp'
                                    )
        }
    }

    #Add component URIs
    $UriResources += $PlatformComponents | %{ "https://graph.microsoft.com/$graphApiVersion/$($_)"}

    #Using -Passthru with Invoke-IDMGraphRequests will out graph data including next link and context. Value contains devices. No Passthru will out value only
    $GraphRequests = $UriResources | Invoke-IDMGraphRequests -Headers $AuthToken -Threads $UriResources.Count

    $DeviceGroups = ($GraphRequests | Where {$_.uri -like '*/devices/*/memberOf'}) | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }}
    $UserGroups = ($GraphRequests | Where {$_.uri -like '*/users/*/memberOf'}) | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }}

    $DeviceGroupMembers = $DeviceGroups | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }},@{N='Target';E={'Devices'}}
    $UserGroupMembers = $UserGroups | Select id, displayName,@{N='GroupType';E={If('DynamicMembership' -in $_.groupTypes){return 'Dynamic'}Else{return 'Static'} }},@{N='Target';E={'Users'}}

    #combine device and users memberships
    $AllGroupMembers = @()
    $AllGroupMembers = $DeviceGroupMembers + $UserGroupMembers

    <#
    $GraphRequests.'@odata.type' | Select -unique
    $GraphRequests.type | Select -unique
    ($GraphRequests.Value | Where '@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration')
    ($GraphRequests.Value | Where '@odata.type' -eq '#microsoft.graph.deviceEnrollmentLimitConfiguration')
    ($GraphRequests.Value | Where '@odata.type' -eq '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration')
    ($GraphRequests.Value | Where '@odata.type' -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration')
    #>
    $PlatformResources = ($GraphRequests | Where {$_.'@odata.type' -match ($PlatformType -join '|')}) |
                                            Select id,uri,
                                                @{N='type';E={Set-IDMResourceFriendlyType -Category (split-path $_.uri -leaf) -ODataType $_.'@odata.type'}},
                                                @{N='name';E={Set-IDMResourceFriendlyName -Name $_.displayName -LicenseType $_.licenseType -ODataType $_.'@odata.type'}},
                                                @{N='Assigned';E={If('isAssigned' -in ($_ | Get-Member -MemberType NoteProperty).Name){[boolean]$_.isAssigned}}}

    <#
    $PlatformResources[35]
    $PlatformResources[418]
    $PlatformResources = $GraphRequests| Select id,@{N='type';E={Set-IDMResourceFriendlyType -Category (split-path $_.uri -leaf) -ODataType $_.'@odata.type'}}, @{N='name';E={If($_.licenseType){$_.displayName + ' (' + $_.licenseType + ')'}Else{$_.displayName}}},@{N='Assigned';E={If('isAssigned' -in ($_ | Get-Member -MemberType NoteProperty).Name){[boolean]$_.isAssigned}}} | ft
    $PlatformResources = $GraphRequests| Select id,uri,@{N='type';E={Set-IDMResourceFriendlyType -Category (split-path $_.uri -leaf) -ODataType $_.'@odata.type'}}, @{N='name';E={If($_.licenseType){$_.displayName + ' (' + $_.licenseType + ')'}Else{$_.displayName}}},'@odata.type',@{N='Assigned';E={If('isAssigned' -in ($_ | Get-Member -MemberType NoteProperty).Name){[boolean]$_.isAssigned}}} | ft
    $PlatformResources.type | Select -unique
    $PlatformResources | Where type -eq 'Policy Set'
    $PlatformResources.type
    #>
    #get Assignments of all resource suing multithreading
    #Using -Passthru with Invoke-IDMGraphRequests will out graph data including next link and context. Value contains devices. No Passthru will out value only
    $ResourceAssignments = $PlatformResources | %{ $_.uri + '/' + $_.id + '/assignments'} | Invoke-IDMGraphRequests -Headers $AuthToken
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
        $AssignmentGroup.Type = $ReferenceResource.Type
        #$AssignmentGroup.Target = $Assignment.target
        $AssignmentGroup.Platform = $Platform
        $AssignmentGroup.Assigned = $ReferenceResource.Assigned

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

Function Set-IDMResourceFriendlyName{
    Param(
        $Name,
        [AllowEmptyString()]
        [string]$LicenseType,

        $ODataType
    )

    If($LicenseType){$FriendlyName = $Name + ' (' + (Get-Culture).TextInfo.ToTitleCase($LicenseType) + ')'}Else{ $FriendlyName = $Name}

    Switch($ODataType){
        '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration' {$FriendlyName = ('(WHfB) ' + $Name)}
        '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration' {$FriendlyName = ('(ESP) ' + $Name)}
        #'#microsoft.graph.windowsUpdateForBusinessConfiguration' {$FriendlyName = ('(WUfB) ' + $Name)}
        default { $FriendlyName = $Name}
    }

    return $FriendlyName
}

Function Set-IDMResourceFriendlyType{
    Param(
        $Category,
        $ODataType
    )

    Switch($Category){
        'windowsAutopilotDeploymentProfiles' {$FriendlyType = 'Autopilot Deployment Profile'}
        'windowsFeatureUpdateProfiles' {$FriendlyType = 'Feature Updates'}
        'roleScopeTags' {$FriendlyType = 'Role Tags'}
        #'deviceEnrollmentConfigurations' {$FriendlyType = 'deviceEnrollment'}
        'windowsInformationProtectionPolicies' {$FriendlyType = 'Windows Information Protection'}
        'deviceManagementScripts' {$FriendlyType = 'PowerShell Scripts'}
        'mdmWindowsInformationProtectionPolicies' {$FriendlyType = 'Windows Information Protection'}
        'deviceCompliancePolicies' {$FriendlyType = 'Compliance Policy'}
        'deviceHealthScripts' {$FriendlyType = 'Endpoint Analytics (Proactive Remediation)'}
        'windowsQualityUpdateProfiles' {$FriendlyType = 'Quality Updates'}
        'mobileApps' {$FriendlyType = 'Apps'}
        'deviceConfigurations' {$FriendlyType = 'Configuration Profile'}
        'policysets' {$FriendlyType = 'Policy Set'}
        default {$FriendlyType = $Category}

    }

    Switch($ODataType){
        #windows
        '#microsoft.graph.azureADWindowsAutopilotDeploymentProfile' {$FriendlyType = ($FriendlyType + ' (Azure AD)')}
        '#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile' {$FriendlyType = ($FriendlyType + ' (Hybrid Join)')}
        '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration' {$FriendlyType = 'Device Restrictions'}
        '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration' {$FriendlyType = '(Autopilot) Windows Hello For Business'}
        '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration' {$FriendlyType = '(Autopilot) Enrollment Status Page'}
        '#microsoft.graph.deviceComanagementAuthorityConfiguration' {$FriendlyType = '(Autopilot) Co-Management Setting'}
        '#microsoft.graph.deviceEnrollmentLimitConfiguration' {$FriendlyType = 'Device Limitation'}
        '#microsoft.graph.windowsUpdateForBusinessConfiguration' {$FriendlyType = 'Windows Update for Business'}
        '#microsoft.graph.windows10CustomConfiguration' {$FriendlyType = ($FriendlyType + ' (Custom)')}
        '#microsoft.graph.windowsDomainJoinConfiguration' {$FriendlyType = ($FriendlyType + ' (Hybrid Domain Join)')}
        '#microsoft.graph.windows10DeviceFirmwareConfigurationInterface' {$FriendlyType = ($FriendlyType + ' (DFCI)')}
        '#microsoft.graph.windowsKioskConfiguration' {$FriendlyType = ($FriendlyType + ' (Kiosk)')}
        '#microsoft.graph.sharedPCConfiguration' {$FriendlyType = ($FriendlyType + ' (Shared PC)')}
        '#microsoft.graph.editionUpgradeConfiguration' {$FriendlyType = ($FriendlyType + ' (Edition Upgrade)')}
        '#microsoft.graph.webApp' {$FriendlyType = ($FriendlyType + ' (Web Link)')}
        '#microsoft.graph.officeSuiteApp' {$FriendlyType = ($FriendlyType + ' (Office 365)')}
    }

    #Common named OData Types
    Switch -wildcard ($ODataType){
        '*ScepCertificateProfile' {$FriendlyType = ($FriendlyType + ' (SCEP)')}
        '*TrustedRootCertificate' {$FriendlyType = ($FriendlyType + ' (Certificate)')}
        '*PkcsCertificateProfile' {$FriendlyType = ($FriendlyType + ' (PKCS Certificate)')}
        '*MicrosoftEdgeApp'     {$FriendlyType = ($FriendlyType + ' (Microsoft Edge)')}
    }

    return $FriendlyType
}