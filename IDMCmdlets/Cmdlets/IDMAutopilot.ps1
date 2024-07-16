
Function Get-IDMAutopilotProfile{
    <#
    .SYNOPSIS
    Gets Windows Autopilot profile details.

    .DESCRIPTION
    The Get-AutopilotProfile cmdlet returns either a list of all Windows Autopilot profiles for the current Azure AD tenant, or information for the specific profile specified by its ID.

    .PARAMETER id
    Optionally, the ID (GUID) of the profile to be retrieved.

    .EXAMPLE
    Get a list of all Windows Autopilot profiles.

    Get-AutopilotProfile
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        $id,
        [Parameter(Mandatory=$false)]
        [switch]$ExpandAssigments,
        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

    # If the ID is set, get the specific profile
    if ($id) {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"
    }

    if ($ExpandAssigments) {
        $uri = $uri + "?`$expand=assignments"
    }

    #Collect the results of the API call
    try {
        Write-Verbose ("Invoking GET API: {0}" -f $uri)
        $graphData = (Invoke-MgGraphRequest -Method Get -Uri $uri)
    }
    catch {
        Write-ErrorResponse($_)
    }

    #detect if the response has a nextLink property
    if ($id) {
        $allPages += $graphData
    }
    else {
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
                Write-ErrorResponse($_)
            }
        }
    }

    If($Passthru){
        return $allPages
    }
    else{
        return (ConvertFrom-GraphHashtable $allPages -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
    }

}




Function Get-IDMAutopilotDevice{
    <#
    .SYNOPSIS
    Gets devices currently registered with Windows Autopilot.

    .DESCRIPTION
    The Get-IDMAutopilotDevice cmdlet retrieves either the full list of devices registered with Windows Autopilot for the current Azure AD tenant, or a specific device if the ID of the device is specified.

    .PARAMETER id
    Optionally specifies the ID (GUID) for a specific Windows Autopilot device (which is typically returned after importing a new device)

    .PARAMETER serial
    Optionally specifies the serial number of the specific Windows Autopilot device to retrieve

    .PARAMETER expand
    Expand the properties of the device to include the Autopilot profile information

    .EXAMPLE
    Get a list of all devices registered with Windows Autopilot

    Get-IDMAutopilotDevice
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0)]
        [string[]]$Id,

        [Parameter(Mandatory=$false)]
        $Serial,

        [Parameter(Mandatory=$false)]
        [Switch]$Expand,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )
    Begin{
        # Defining graph variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"

        $allPages = @()
        $devices = @()
    }
    Process {

        if ($id -and $Expand) {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$($id)?`$expand=deploymentProfile,intendedDeploymentProfile"
        }
        elseif ($id) {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$id"
        }
        elseif ($serial) {
            $encoded = [uri]::EscapeDataString($serial)
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
        }
        else {
            $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"
        }

        #Collect the results of the API call
        try {
            Write-Verbose ("Invoking GET API: {0}" -f $uri)
            $graphData = (Invoke-MgGraphRequest -Method Get -Uri $uri)
        }
        catch {
            Write-ErrorResponse($_)
        }

        #detect if the response has a nextLink property
        if ($id) {
            $allPages += $graphData
        }
        else {
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
                    Write-ErrorResponse($_)
                }
            }
        }

    }End{
        if ( ($Null -eq $id) -and $Expand) {
            $devices += $allPages.id | Get-IDMAutopilotDevice -Expand
        }
        else {
            $devices += $allPages
        }

        Write-Verbose "Returning $($devices.Count) devices"
        If($Passthru){
            return $devices
        }
        else{
            return (ConvertFrom-GraphHashtable $devices -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
        }
    }
}


Function Set-IDMAutopilotDeviceTag{
    <#
    .SYNOPSIS
    Updates grouptag for Autopilot device.

    .DESCRIPTION
    The Set-IDMAutopilotDeviceTag cmdlet can be used to change the updatable properties on a Windows Autopilot device object.

    .PARAMETER id
    The Windows Autopilot device id (mandatory).

    .PARAMETER userPrincipalName
    The user principal name.

    .PARAMETER addressibleUserName
    The name to display during Windows Autopilot enrollment. If specified, the userPrincipalName must also be specified.

    .PARAMETER displayName
    The name (computer name) to be assigned to the device when it is deployed via Windows Autopilot. This is presently only supported with Azure AD Join scenarios. Note that names should not exceed 15 characters. After setting the
    name, you need to initiate a sync (Invoke-AutopilotSync) in order to see the name in the Intune object.

    .PARAMETER groupTag
    The group tag value to set for the device.

    .EXAMPLE
    Assign a user and a name to display during enrollment to a Windows Autopilot device.

    Set-IDMAutopilotProfileTag -AutopilotID $id -GroupTag "Testing"
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        $AutopilotID,

        [Parameter(Mandatory=$false)]
        $GroupTag
    )
    Begin{
         # Defining graph variables
         $graphApiVersion = "beta"
         $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
    }
    Process {
        #TEST $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/c50d642a-e8d7-4f84-9dc2-3540303b1acf/UpdateDeviceProperties"
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$AutopilotID/UpdateDeviceProperties"

        $requestBody = @{ groupTag = $groupTag }
        $BodyJson = $requestBody | ConvertTo-Json

        <#
        $BodyJson = "{"
        $BodyJson += " groupTag: `"$groupTag`""
        $BodyJson += " }"
        #>

        try {
            Write-Verbose ("Invoking POST API: {0}" -f $uri)
            $null = Invoke-MgGraphRequest -Uri $uri -Body $BodyJson -Method POST -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
}


Function Add-IDMAutopilotProfileToDevice{

    <#
    .SYNOPSIS
    Assigns a Windows Autopilot profile to a device.

    .DESCRIPTION
    The Add-AutopilotProfileToDevice cmdlet assigns a Windows Autopilot profile to a device.

    .PARAMETER APProfileId
    The ID of the Windows Autopilot profile to assign to the device.

    .PARAMETER DeviceID
    The ID of the device to assign the Windows Autopilot profile to.

    .EXAMPLE
    Assign a Windows Autopilot profile to a device.

    Add-AutopilotProfileToDevice -APProfileId "c50d642a-e8d7-4f84-9dc2-3540303b1acf" -deviceID "c50d642a-e8d7-4f84-9dc2-3540303b1acf"
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        $APProfileId,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        $DeviceID
    )
    Begin{
        # Defining graph variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    }
    Process {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$APProfileId/assign"
        $requestBody = @{ deviceIds = @($deviceID) }
        $BodyJson = $requestBody | ConvertTo-Json

        try {
            Write-Verbose ("Invoking POST API: {0}" -f $uri)
            $null = Invoke-MgGraphRequest -Uri $uri -Body $BodyJson -Method POST -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }

}