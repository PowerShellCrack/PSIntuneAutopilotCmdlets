Function Get-IDMCompliancePolicies {
    <#
    .SYNOPSIS
    Get the compliance policies in Intune.

    .DESCRIPTION
    This cmdlet retrieves the compliance policies in Intune.

    .PARAMETER PolicyId
    The ID of the compliance policy to retrieve.

    .PARAMETER Passthru
    Return the raw data from the Graph API.

    .EXAMPLE
    Get-IDMCompliancePolicies

    .EXAMPLE
    Get-IDMCompliancePolicies -PolicyId "b79cb75a-2dd7-496e-b9af-13f0e9e2bba0"

    .EXAMPLE
    Get-IDMCompliancePolicies -Passthru

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$PolicyId,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
    # If the ID is set, get the specific profile
    if ($PolicyId) {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$PolicyId"
    }
    else {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"
    }

    #Collect the results of the API call
    try {
        Write-Verbose ("Invoking API: {0}" -f $uri)
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
            return (ConvertFrom-GraphHashtable $allPages -ResourceUri $uri)
        }
    }

}


Function Update-IDMCompliancePolicyOSVersion{

    <#
    .SYNOPSIS
    Set the compliance policies in Intune.  

    .DESCRIPTION
    This cmdlet sets the compliance policies in Intune.

    .PARAMETER PolicyId
    The ID of the compliance policy to set.

    .PARAMETER OSVersionType
    The Property of the compliance policy to update

    .PARAMETER Passthru
    The compliance policy to set.
    
    .EXAMPLE
    Update-IDMCompliancePolicyOSVersion -PolicyId "b79cb75a-2dd7-496e-b9af-13f0e9e2bba0" -OSVersionType "MinimumVersion" -OSVersion "10.0.19041.0"

    .EXAMPLE
    Update-IDMCompliancePolicyOSVersion -PolicyId "58aaee1b-9930-4c56-8135-722e7efa327f" -OSVersionType "MaximumVersion" -OSVersion "14"
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [string]$PolicyId,

        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumVersion","MaximumVersion")]
        [string]$OSVersionType,

        [Parameter(Mandatory=$true)]
        [string]$OSVersion,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"

    $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource/$PolicyId"

    $Policy = Get-IDMCompliancePolicies -PolicyId $PolicyId

    If($Null -ne $Policy){
        #Update the OS version
        switch($OSVersionType){
            "MinimumVersion"{
                $Policy.osMinimumVersion = $OSVersion
            }
            "MaximumVersion"{
                $Policy.osMaximumVersion = $OSVersion
            }
        }

        #Convert the hashtable to JSON
        $Payload = $Policy | Select-Object -ExcludeProperty uri,id,version  | ConvertTo-Json -Depth 10
        
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

Function Get-IDMWindowsUpdateCatalog{
    <#
    
    .SYNOPSIS
    Get the Windows Update Catalog.

    .DESCRIPTION
    This cmdlet retrieves the Windows Update Catalog.

    .PARAMETER ProductName
    The name of the product to retrieve.

    .PARAMETER Passthru
    Return the raw data from the Graph API.

    .EXAMPLE
    Get-IDMWindowsUpdateCatalog

    .EXAMPLE
    Get-IDMWindowsUpdateCatalog -ProductName "Windows 10"

    .EXAMPLE
    Get-IDMWindowsUpdateCatalog -Passthru

    .NOTES
    https://graph.microsoft.com/beta/admin/windows/updates/catalog/entries
    https://learn.microsoft.com/en-us/graph/api/resources/windowsupdates-product?view=graph-rest-beta
    https://techcommunity.microsoft.com/t5/windows-it-pro-blog/public-preview-of-microsoft-graph-apis-to-manage-windows-updates/ba-p/2302751

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [string]$ProductName,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    $graphApiVersion = "beta"
    $Resource = "admin/windows/updates/catalog/entries"

    # If the name is set, get the specific profile""
    if ($ProductName) {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource`?`$filter=contains(displayName,'$($ProductName)')"
    }
    else {
        $uri = "$Global:GraphEndpoint/$graphApiVersion/$Resource"
    }

    #Collect the results of the API call
    try {
        Write-Verbose ("Invoking API: {0}" -f $uri)
        $graphData = (Invoke-MgGraphRequest -Method Get -Uri $uri)
    }
    catch {
        Write-ErrorResponse($_)
    }

    #detect if the response has a nextLink property
    if ($ProductName) {
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

Function Get-IDMCompliancePolicyOSRelease{
    <#
    .SYNOPSIS
    Get the latest OS release for a specific platform.

    .DESCRIPTION
    This cmdlet retrieves the latest OS release for a specific platform.

    .PARAMETER Platform
    The platform to retrieve the latest OS release for.

    .PARAMETER Latest
    Get the latest OS release.

    .PARAMETER Passthru
    Return the raw data from the Graph API.

    .EXAMPLE
    Get-IDMCompliancePolicyOSRelease -Platform Windows11

    .EXAMPLE
    Get-IDMCompliancePolicyOSRelease -Platform iOS -Latest

    .EXAMPLE
    Get-IDMCompliancePolicyOSRelease -Platform Windows10 -Passthru

    .NOTES
    https://endoflife.date
    
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Windows11","Windows10","iOS","Android","macOS","Ubuntu","RHEL")]
        [string]$Platform,

        [Parameter(Mandatory=$false)]
        [switch]$Latest,

        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    #Get the OS version
    switch($Platform){
        "Windows11"{
            #get latest OS version for Windows 11
            $url = "https://endoflife.date/api/windows.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json | Where-Object releaseLabel -like "11*"
            $property = 'latest'
        }
        "Windows10"{
            #get latest OS version for Windows 10
            $url = "https://endoflife.date/api/windows.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json | Where-Object releaseLabel -like "10*"
            $property = 'latest'
        }
        "iOS"{
            #get latest OS version for iOS
            $url = "https://endoflife.date/api/ios.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json
            $property = 'latest'
        }
        "Android"{
            #get latest OS version for Android
            $url = "https://endoflife.date/api/android.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json
            $property = 'cycle'
        }
        "macOS"{
            #get latest OS version for macOS
            $url = "https://endoflife.date/api/macos.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json
            $property = 'latest'
        }
        "Ubuntu"{
            #get latest OS version for Ubuntu
            $url = "https://endoflife.date/api/ubuntu.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json
            $property = 'latest'
        }
        "RHEL"{
            #get latest OS version for RHEL
            $url = "https://endoflife.date/api/rhel.json"
            Write-Verbose ("Invoking GET URL: {0}" -f $url)
            $OSRelease  = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing | ConvertFrom-Json
            $property = 'latest'
        }

    }

    If($Latest){
        $OSRelease = $OSRelease | Select -First 1
    }

    If($Passthru){
        return $OSRelease
    }
    else{
        return $OSRelease.$property
    }
}