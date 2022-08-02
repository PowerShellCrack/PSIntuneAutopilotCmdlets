#https://stackoverflow.com/questions/18771424/how-to-get-powershell-invoke-restmethod-to-return-body-of-http-500-code-response
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
            Write-Error $ResponseBody
        }
    }
    else {
        Write-Error $ErrorResponse.ErrorDetails.Message
    }
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
