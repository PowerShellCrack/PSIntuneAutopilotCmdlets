
#set the graph endpoint
$Global:GraphEndpoint = 'https://graph.microsoft.com'
$PolicyId = "b79cb75a-2dd7-496e-b9af-13f0e9e2bba0"

#IMPORT MODULES
#==============================================

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
#Connect-IDMGraphApp -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

#Set the latest Windows 11 OS release as the minimum version for the compliance policy
$MiniOS = Get-IDMCompliancePolicyOSRelease -Platform "Windows11" -Latest
Update-IDMCompliancePoliciesOSVersion -OSVersionType MinimumVersion -PolicyId $PolicyId -OSVersion $MiniOS