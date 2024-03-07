
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
        $id
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

    # If the ID is set, get the specific profile
    if ($id) {
        $uri = "$Global:graphEndpoint/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "$Global:graphEndpoint/$graphApiVersion/$Resource"
    }

    # add method to the request, Exclude URI from the request so that it won't concflict with nextLink URI

    Write-Verbose "GET $uri"

    try {
        $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
        if ($id) {
            $response
        }
        else {
            $devices = $response.value

            $devicesNextLink = $response."@odata.nextLink"

            while ($null -ne $devicesNextLink){
                $devicesResponse = (Invoke-MgGraphRequest -Uri $devicesNextLink -Method Get)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }

            $devices
        }
    }
    catch {
        Write-ErrorResponse($_)
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)]
        $id,

        [Parameter(Mandatory=$false)]
        $serial,

        [Parameter(Mandatory=$false)]
        [Switch]$expand
    )

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"

        if ($id -and $expand) {
            $uri = "$Global:graphEndpoint/$graphApiVersion/$($Resource)/$($id)?`$expand=deploymentProfile,intendedDeploymentProfile"
        }
        elseif ($id) {
            $uri = "$Global:graphEndpoint/$graphApiVersion/$($Resource)/$id"
        }
        elseif ($serial) {
            $encoded = [uri]::EscapeDataString($serial)
            $uri = "$Global:graphEndpoint/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
        }
        else {
            $uri = "$Global:graphEndpoint/$graphApiVersion/$($Resource)"
        }

        Write-Verbose "GET $uri"

        try {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get -ErrorAction Stop
            if ($id) {
                $response
            }
            else {
                $devices = $response.value
                $devicesNextLink = $response."@odata.nextLink"

                while ($null -ne $devicesNextLink){
                    $devicesResponse = (Invoke-MgGraphRequest -Uri $devicesNextLink -Method Get -ErrorAction Stop)
                    $devicesNextLink = $devicesResponse."@odata.nextLink"
                    $devices += $devicesResponse.value
                }

                if ($expand) {
                    $devices | Get-IDMAutopilotDevice -Expand
                }
                else
                {
                    $devices
                }
            }
        }
        catch {
            Write-ErrorResponse($_)
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
         # Defining Variables
         $graphApiVersion = "beta"
         $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
    }
    Process {
        #TEST $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/c50d642a-e8d7-4f84-9dc2-3540303b1acf/UpdateDeviceProperties"
        $uri = "$Global:graphEndpoint/$graphApiVersion/$Resource/$AutopilotID/UpdateDeviceProperties"

        $requestBody = @{ groupTag = $groupTag }
        $BodyJson = $requestBody | ConvertTo-Json

        <#
        $BodyJson = "{"
        $BodyJson += " groupTag: `"$groupTag`""
        $BodyJson += " }"
        #>

        try {
            Write-Verbose "GET $uri"
            $null = Invoke-MgGraphRequest -Uri $uri -Body $BodyJson -Method POST -ErrorAction Stop
        }
        catch {
            Write-ErrorResponse($_)
        }
    }
}
