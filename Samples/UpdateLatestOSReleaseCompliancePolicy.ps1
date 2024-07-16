<#
.SYNOPSIS
    This script will update the minimum OS version of a compliance policy and app protection policy to the latest iOS/Android release.

.DESCRIPTION
    This script will update the minimum OS version of a compliance policy to the latest iOS/Android release.

.EXAMPLE
    .\UpdateLatestOSReleaseCompliancePolicy.ps1

.NOTES
    File Name      : UpdateLatestOSReleaseCompliancePolicy.ps1
    Author         : Powershellcrack

#>
#SET THE POLICY IDS
$iOSCompliancePolicyId = "712599b4-c442-49d4-867c-a92fc2da371a"
$iOSAppProtectPolicyId = "T_2824c38c-9fa8-4f7e-af7c-e98fe2cc4c78"

$AndriodCompliancePolicyId = "58aaee1b-9930-4c56-8135-722e7efa327f"
$AndriodAppProtectPolicyId = "T_6ffb82b6-fbbd-4b68-bab8-15fa2860ca3b"

#IMPORT MODULES
#==============================================
#Set Azure Commercial Endpoint
$Global:GraphEndpoint = 'https://graph.microsoft.com'

#install required modules
$modules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'IDMCmdlets'
)

foreach ($module in $modules){
    Write-Host ("Checking for installed module: {0}..." -f $module) -ForegroundColor White
    If((Find-Module $module).Version -in (Get-InstalledModule $module -AllVersions).version)
    {
        Write-Host ("  |--Version [{0}] installed" -f (Get-InstalledModule $module -AllVersions).version) -ForegroundColor Green
    }
    Else{
        Write-Host ("  |--Updating, please wait..." )-ForegroundColor Yellow -NoNewline
        Install-Module -Name $module -AllowClobber -Force
        Write-Host "Done" -ForegroundColor Green
    }
}

#MAIN
#==============================================


Write-Host '----------------------------------------' -ForegroundColor White
#connect to the graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor White -NoNewline
Connect-MgGraph -NoWelcome

#connect to the grpah using a service principal
#Connect-IDMGraphApp -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret


#get the latest iOS release
$iOSLatestOS = Get-IDMCompliancePolicyOSRelease -Platform iOS -Latest

#Set the latest iOS release as the minimum version for the compliance policy and app protection policy
Update-IDMCompliancePolicyOSVersion -PolicyId $iOSCompliancePolicyId -OSVersionType MinimumVersion -OSVersion $iOSLatestOS
Update-IDMAppProtectionPolicyOSCondition -Platform iOS -PolicyId $iOSAppProtectPolicyId -OSCondition MinimumVersion -OSVersion $iOSLatestOS

#get the latest Android release
$AndroidLatestOS = Get-IDMCompliancePolicyOSRelease -Platform Android -Latest

#Set the latest Android release as the minimum version for the compliance policy and app protection policy
Update-IDMCompliancePolicyOSVersion -PolicyId $AndriodCompliancePolicyId -OSVersionType MinimumVersion -OSVersion $AndroidLatestOS
Update-IDMAppProtectionPolicyOSCondition -Platform Android -PolicyId $AndriodAppProtectPolicyId -OSCondition MinimumVersion -OSVersion $AndroidLatestOS
