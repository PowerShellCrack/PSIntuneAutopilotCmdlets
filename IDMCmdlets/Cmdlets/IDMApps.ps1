
Function Get-IDMDetectedApps{
    <#
    .SYNOPSIS
    Get all detected apps from the Intune Graph API

    .DESCRIPTION
    This function will get all detected apps from the Intune Graph API


    .PARAMETER id
    The ID of the detected app to get

    .EXAMPLE
    Get-IDMDetectedApps

    This example retrieves all detected apps from the Intune Graph API

    .EXAMPLE
    Get-IDMDetectedApps -id "3a18fdec538b6f739a0d028c9508bbc2594c94323b1873da959c99d65e0c9f05"

    This example retrieves a specific detected app from the Intune Graph API

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        $id,
        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/detectedApps"

    # If the ID is set, get the specific profile
    if ($id) {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"
    }

    # add method to the request, Exclude URI from the request so that it won't concflict with nextLink URI

    Write-Verbose "GET $uri"

    #Collect the results of the API call
    try {
        Write-Verbose ("Invoking API: {0}" -f $uri)
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

    If($Null -ne $allPages){
        If($Passthru){
            return $allPages
        }
        else{
            return (ConvertFrom-GraphHashtable $allPages -ResourceUri $uri)
        }
    }

}


Function Get-IDMManagedDevicesForApp{
    <#
    .SYNOPSIS
    Get all managed devices for a detected app from the Intune Graph API

    .DESCRIPTION
    This function will get all managed devices for a detected app from the Intune Graph API

    .PARAMETER Appid
    The ID of the detected app to get managed devices for

    .EXAMPLE
    Get-IDMManagedDevicesForApp -AppId "3a18fdec538b6f739a0d028c9508bbc2594c94323b1873da959c99d65e0c9f05"

    This example retrieves all managed devices for a detected app from the Intune Graph API


    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $AppId,
        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    # Defining graph variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/detectedApps"

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$AppId/managedDevices"
    # add method to the request, Exclude URI from the request so that it won't concflict with nextLink URI

    Write-Verbose "GET $uri"

    #Collect the results of the API call
    try {
        Write-Verbose ("Invoking API: {0}" -f $uri)
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

    If($Null -ne $allPages){
        If($Passthru){
            return $allPages
        }
        else{
            return (ConvertFrom-GraphHashtable $allPages -ResourceUri $uri)
        }
    }
}