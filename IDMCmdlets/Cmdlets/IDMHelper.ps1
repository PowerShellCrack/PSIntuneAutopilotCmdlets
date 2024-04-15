#https://stackoverflow.com/questions/18771424/how-to-get-powershell-Invoke-MgGraphRequest-to-return-body-of-http-500-code-response
function Write-ErrorResponse($ErrorResponse) {

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($ErrorResponse.Exception.Response) {
            $Reader = New-Object System.IO.StreamReader($ErrorResponse.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json
            }
            Write-Host ("{0}: {1}" -f $ErrorResponse,$ResponseBody) -ForegroundColor Red
        }Else{
            Write-Host $ErrorResponse -ForegroundColor Red
        }
    }
    else {
        Write-Host $ErrorResponse.ErrorDetails.Message -ForegroundColor Red
    }
}

Function Test-JSON{
    <#
    .SYNOPSIS
    This function is used to test if the JSON passed to a REST Post request is valid

    .DESCRIPTION
    The function tests if the JSON passed to the REST Post is valid

    .EXAMPLE
    Test-JSON -JSON $JSON
    Test if the JSON is valid before calling the Graph REST interface
    #>

    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $validJson = $true

    }
    catch {
        $validJson = $false
        $_.Exception
    }

    Return $validJson

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

    If($FriendlyName){
        return $FriendlyName
    }Else{
        return $Name
    }
}

Function Set-IDMResourceFriendlyType{

    Param(
        $Category,
        $ODataType
    )

    Switch($Category){
        'advancedThreatProtectionOnboardingStateSummary' {$FriendlyType = 'Windows Defender Advanced Threat Protection Onboarding'}
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


function Split-IDMRequests {
    <#
    .SYNOPSIS
    Split an array into groups

    .PARAMETER CollectionUri
    Provide Uri in array format

    .PARAMETER GroupOf
    Set the amount each  grouped array will consist of. Graph Batch process cap is 20.

    .EXAMPLE
     $Uri = @(
            'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies'
            'https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts'
            'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
            'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations'
            'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
            'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
            'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags'
            'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles'
            'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles'
            'https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies'
            'https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies'
            'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
            'https://graph.microsoft.com/beta/deviceAppManagement/policysets'
    )
    $Uri | %{ $_.uri + '/' + $_.id + '/assignments'} |
                Split-IDMRequests -GroupOf 20 | ForEach-Object { $_ | Invoke-IDMGraphBatchRequests -Verbose:$VerbosePreference}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [array]$CollectionUri,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 20)]
        [int] $GroupOf = 20
    )
    begin {
        $Ctr = 0
        $Array = @()
        $TempArray = @()
    }
    process {
        foreach ($e in $CollectionUri) {
            if (++$Ctr -eq $GroupOf) {
                $Ctr = 0
                $Array += , @($TempArray + $e)
                $TempArray = @()
                continue
            }
            $TempArray += $e
        }
    }
    end {
        if ($TempArray) { $Array += , $TempArray }
        return $Array
    }
}


Function ConvertFrom-GraphHashtable{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        $GraphData,

        [Parameter(Mandatory=$false)]
        [string]$ResourceUri,

        [Parameter(Mandatory=$false)]
        [string]$ResourceAppend
    )

    Begin{
        $GraphObject = @()
    }
    Process{

        #$hashtable = @{}
        #TEST $item = $body.value[0]
        #TEST $item = $graphData[0]
        Foreach($Item in $graphData)
        {
            If(Test-Hashtable $Item)
            {
                $hashtable = @{}

                Write-Verbose "Processing Hashtable"
                foreach( $property in $Item.GetEnumerator() )
                {
                    #$hashtable[$property] = $Item.$property
                    $hashtable[$property.Name] = $property.Value
                }
                If($ResourceUri){
                    Write-verbose "Adding URI to item..."
                    $ItemURI = ($ResourceUri + '/' + $item.id + "/" + $ResourceAppend).Trim('/')
                    $hashtable['uri'] = $ItemURI
                }
                #$hashtable['type'] = (Split-Path $Element.'@odata.context' -Leaf).replace('$metadata#','')
                $Object = New-Object PSObject -Property $hashtable
                $GraphObject += $Object
            }
            Else{
                Write-Verbose "Processing Object"
                If($ResourceUri){
                    If($Item.uri){
                        Write-Verbose "URI Exists, overwriting..."
                        $Item.uri = ($ResourceUri + '/' + $item.id + "/" + $ResourceAppend).Trim('/')
                    }Else{
                        $Item | Add-Member -MemberType NoteProperty -Name 'uri' -Value ($ResourceUri + '/' + $item.id + "/" + $ResourceAppend).Trim('/')
                    }
                }
                $GraphObject += $Item

            }
        }

    }
    End{
        return $GraphObject
    }
}


#test if object is a hashtable
function Test-Hashtable{
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        $Object
    )

    Begin{
        $isHashtable = $false
    }
    Process{
        if($Object -is [hashtable]){
            $isHashtable = $true
        }
    }
    End{
        return $isHashtable
    }
}