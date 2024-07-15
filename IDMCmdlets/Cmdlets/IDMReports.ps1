Function Get-IDMIntuneReportForDevice{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DeviceId,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Devices','Configuration','Compliance','Apps')]
        [string]$ReportType,
        [Parameter(Mandatory=$true)]
        [string]$ReportPath
    )

    Begin{
        switch($ReportType){
            
            'Configuration' {
                $filter = @"
((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or 
(PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') or 
(PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') or 
(PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent')) and 
(IntuneDeviceId eq '$DeviceId')
"@               
                $JsonBody = @{
                    reportName = 'Devices'
                    filter = [string]::join("",($filter.Split("`n")))
                    select = @('PolicyName','UPN','PolicyType','PolicyStatus')
                } | ConvertTo-Json
            }

            'Compliance'{
               
            }
            'Apps'{
                
            }
        }
    }
    Process{
        
    }
    End{
        
    }
}