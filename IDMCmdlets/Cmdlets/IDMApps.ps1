
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

    If($Null -ne $allPages){
        If($Passthru){
            return $allPages
        }
        else{
            return (ConvertFrom-GraphHashtable $allPages -ResourceUri $uri)
        }
    }
}



Function Get-IDMAppProtectionPolicies {
    <#
    .SYNOPSIS
    Get the App Protection policies in Intune.

    .DESCRIPTION
    This cmdlet retrieves the App Protection policies in Intune.

    .PARAMETER PolicyId
    The ID of the App Protection policy to retrieve.

    .PARAMETER Passthru
    Return the raw data from the Graph API.

    .EXAMPLE
    Get-IDMAppProtectionPolicies -Platform iOS

    .EXAMPLE
    Get-IDMAppProtectionPolicies -Platform iOS -PolicyId "T_2824c38c-9fa8-4f7e-af7c-e98fe2cc4c78"

    .EXAMPLE
    Get-IDMAppProtectionPolicies -Platform Android -Passthru

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("iOS","Android")]
        [string]$Platform,
        
        [Parameter(Mandatory=$false)]
        [string]$PolicyId,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )
    $graphApiVersion = "beta"

    switch ($Platform) {
        "iOS" {
            $Resource = "deviceAppManagement/iosManagedAppProtections"
        }
        "Android" {
            $Resource = "deviceAppManagement/androidManagedAppProtections"
        }
    }
    
    # If the ID is set, get the specific profile
    if ($PolicyId) {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$PolicyId"
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
    if ($PolicyId) {
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
            return (ConvertFrom-GraphHashtable $allPages -ResourceUri "$Global:GraphEndpoint/$graphApiVersion/$Resource")
        }
    }

}


Function Update-IDMAppProtectionPolicyOSCondition{

    <#
    .SYNOPSIS
    Set the app protection policy OS condition for mobile in Intune.

    .DESCRIPTION
    Set the app protection policy OS condition for mobile in Intune.

    .PARAMETER PolicyId
    The ID of the app protection policy to set.

    .PARAMETER OSCondition
    The OS condition property the app protection policy to update

    .PARAMETER Passthru
    The compliance policy to set.
    
    .EXAMPLE
    Update-IDMAppProtectionPolicyOSCondition -Platform iOS -PolicyId "T_2824c38c-9fa8-4f7e-af7c-e98fe2cc4c78" -OSCondition "MinimumVersion" -OSVersion "17.5"

    .EXAMPLE
    Update-IDMAppProtectionPolicyOSCondition -Platform Andriod -PolicyId "T_6ffb82b6-fbbd-4b68-bab8-15fa2860ca3b" -OSCondition "MaximumVersion" -OSVersion "14"
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$PolicyId,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("iOS","Android")]
        [string]$Platform,

        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumVersion","MaximumVersion")]
        [string]$OSCondition,

        [Parameter(Mandatory=$true)]
        [string]$OSVersion,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    $graphApiVersion = "beta"
    switch ($Platform) {
        "iOS" {
            $Resource = "deviceAppManagement/iosManagedAppProtections"
        }
        "Android" {
            $Resource = "deviceAppManagement/androidManagedAppProtections"
        }
    }

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$PolicyId"

    $Policy = Get-IDMAppProtectionPolicies -Platform $Platform -PolicyId $PolicyId

    If($Null -ne $Policy){
        #Update the OS version
        switch($OSCondition){
            "MinimumVersion"{
                $Policy.minimumRequiredOsVersion = $OSVersion
            }
            "MaximumVersion"{
                $Policy.maximumRequiredOsVersion = $OSVersion
            }
        }

        #Convert the hashtable to JSON
        $Payload = $Policy | Select-Object -ExcludeProperty uri,id,version | ConvertTo-Json -Depth 10
        Write-Debug $Payload
        #Update the compliance policy
        try {
            Write-Verbose ("Invoking PATCH API: {0}" -f $uri)
            Invoke-MgGraphRequest -Method Patch -Uri $uri -Body $Payload
        }
        catch {
            Write-ErrorResponse($_)
        }
    }Else{
        Write-Error "Compliance Policy not found with ID: $PolicyId"
        Return $False
    }
}