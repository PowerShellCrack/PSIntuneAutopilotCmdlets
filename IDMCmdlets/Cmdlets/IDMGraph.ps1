Function Connect-IDMGraphApp {
    <#
    .SYNOPSIS
    Authenticates to the Graph API via the Microsoft.Graph.Intune module using app-based authentication.

    .DESCRIPTION
    The Connect-IDMGraphApp cmdlet is a wrapper cmdlet that helps authenticate to the Graph API using the Microsoft.Graph.Intune module.
    It leverages an Azure AD app ID and app secret for authentication. See https://oofhours.com/2019/11/29/app-based-authentication-with-intune/ for more information.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#create-a-new-application-secret

    .PARAMETER Tenant
    Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

    .PARAMETER AppId
    Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

    .PARAMETER AppSecret
    Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

    .EXAMPLE
    Connect-IDMGraphApp -TenantId $TenantID -AppId $app -AppSecret $secret
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [Alias('ClientId')]
        [String]$AppId,

        [Parameter(Mandatory=$true)]
        [Alias('Tenant')]
        [String]$TenantID,

        [Parameter(Mandatory=$true)]
        [Alias('ClientSecret')]
        [String]$AppSecret
    )
    try {
        #convert secret into creds
        $azurePassword = ConvertTo-SecureString $AppSecret -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($AppId , $azurePassword)

        #connect to Azure using App service principal
        Connect-AzAccount -Credential $psCred -TenantId $TenantID -ServicePrincipal | Out-Null

        #Grab the Azure context which will include Azure Token
        $context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, `
                                                $context.Environment, $context.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, `
                                                $null, "https://graph.windows.net").AccessToken

        $Body = @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            client_Id     = $AppId
            Client_Secret = $AppSecret
        }
        $ConnectGraph = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $Body -ErrorAction Stop
        $token = $ConnectGraph.access_token
        #format the date correctly
        $ExpiresOnMinutes = $ConnectGraph.expires_in / 60
        $ExpiresOn = (Get-Date).AddMinutes($ExpiresOnMinutes).ToString("M/d/yyyy hh:mm tt +00:00")

        # Creating header for Authorization token
        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $token
            'ExpiresOn'=$ExpiresOn
        }
        return $authHeader
    }
    Catch{
        Write-Error ("{0}: {1}" -f $_.Exception.ItemName, $_.Exception.Message)
    }
}

function Get-IDMGraphAuthToken{

    <#
    .SYNOPSIS
        This function is used to authenticate with the Graph API REST interface

    .DESCRIPTION
        The function authenticate with the Graph API Interface with the tenant name

    .PARAMETER User
        Must be in UPN format (email). This is the user principal name (eg user@domain.com)

    .EXAMPLE
        Get-IDMGraphAuthToken
        Authenticates you with the Graph API interface

    .NOTES
    Requires: AzureAD Module

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Net.Mail.MailAddress]$User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {
        Write-Error "AzureAD Powershell module not installed. Install by running 'Install-Module AzureAD' from an elevated PowerShell prompt"
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    if($AadModule.count -gt 1)
    {
        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
        # Checking if there are multiple versions of the same module found
        if($AadModule.count -gt 1){
            $aadModule = $AadModule | select -Unique
        }
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    else {
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    #$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    #$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"

    try {
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behavior to force credentials each time: Auto, Always, Never, RefreshSession
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header
        if($authResult.AccessToken){

            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
            }
            return $authHeader
        }
        else {
            Write-Error "Authorization Access Token is null, please re-run authentication..."
        }
    }
    catch {
        Write-Error ("{0}: {1}" -f $_.Exception.ItemName, $_.Exception.Message)
    }
}


function Update-IDMGraphAccessToken{
    <#
    .SYNOPSIS
        Refreshes an access token based on refresh token

    .PARAMETER Token
        Token is the existing refresh token

    .PARAMETER tenantID
        This is the tenant ID in GUID format

    .PARAMETER ClientID
        This is the app reg client ID in GUID format

    .PARAMETER Secret
        This is the client secret

    .PARAMETER Scope
        An array of access scope, default is: "Group.ReadWrite.All" & "User.ReadWrite.All"

    .LINK
        Reference: https://docs.microsoft.com/en-us/graph/auth-v2-user#3-get-a-token
    #>
    Param(
        [parameter(Mandatory = $true)]
        [String]$Token,

        [parameter(Mandatory = $true)]
        [String]$TenantID,

        [parameter(Mandatory = $true)]
        [String]$ClientID,

        [parameter(Mandatory = $true)]
        [String]$Secret,

        [parameter(Mandatory = $false)]
        [String[]]$Scope = @("Group.ReadWrite.All","User.ReadWrite.All")
    )

    # Defining Variables
    $graphApiVersion = "v2.0"
    $Resource = "token"

    $uri = "https://login.microsoftonline.com/$TenantID/oauth2/$graphApiVersion/$Resource"

    $bodyHash = @{
        client_id = $ClientID
        scope = ($Scope -join ' ')
        refresh_token = $Token
        #redirect_uri =' http://localhost'
        redirect_uri = 'https://graph.microsoft.com/.default'
        grant_type = 'refresh_token'
        client_secret = $Secret
    }
    $body = ($bodyHash.GetEnumerator() | Foreach {$_.key +'='+ [System.Web.HttpUtility]::UrlEncode($_.Value)}) -Join '&'

    try {
        Write-Verbose "GET $uri"
        $Response = Invoke-RestMethod -Uri $uri -body $body -ContentType 'application/x-www-form-urlencoded' -Method Post -ErrorAction Stop
    }
    catch {
        Write-ErrorResponse($_)
    }
    return $Response
}

Function Invoke-IDMGraphBatchRequests{
<#
    .SYNOPSIS
        Invoke GET method to Microsoft Graph Rest API using batch method

    .DESCRIPTION
        Invoke Rest method using the get method but do it using collection of Get requests as one batch request

    .PARAMETER $Uri
        Specify graph uri(s) for requests

    .PARAMETER Headers
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        $AuthToken = Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .PARAMETER Passthru
        Using -Passthru will out graph data including next link and context. Value contains devices.
        No Passthru will out value only

    .EXAMPLE
        $Uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
        Invoke-IDMGraphBatchRequests -Uri $Uri -Headers $AuthToken

    .EXAMPLE
        $UriResources = @(
            'https://graph.microsoft.com/beta/users/c9d00ac2-b07d-4477-961b-442bbc424586/memberOf'
            'https://graph.microsoft.com/beta/devices/b215decf-4188-4d19-9e22-fb2e89ae0fec/memberOf'
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
        $Response = $UriResources | Invoke-IDMGraphBatchRequests -Headers $Global:AuthToken -verbose

    .EXAMPLE
        Invoke-IDMGraphBatchRequests -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Headers $Global:AuthToken -Passthru

    .LINK
        https://docs.microsoft.com/en-us/graph/sdks/batch-requests?tabs=csharp
        https://docs.microsoft.com/en-us/graph/json-batching
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,HelpMessage="Specify Uri or array or Uris")]
        [string[]]$Uri,

        [Parameter(Mandatory=$false)]
        [hashtable]$Headers = $Global:AuthToken,

        [switch]$Passthru
    )
    Begin{
        $graphApiVersion = "beta"
        $Method = 'GET'
        $batch = @()
        $i = 1
        #Build custom object for assignment
        $BatchProperties = "" | Select requests
    }
    Process{
        Foreach($url in $Uri | Select -Unique){
            $URLRequests = "" | Select id,method,url
            $URLRequests.id = $i
            $URLRequests.method = $Method
            $URLRequests.url = $url.replace("https://graph.microsoft.com/$graphApiVersion",'')
            $i++
            $batch += $URLRequests
        }
    }
    End{
        $BatchProperties.requests = $batch
        #convert body to json
        $BatchBody = $BatchProperties | ConvertTo-Json

        Write-Verbose $BatchBody
        $batchUri = "https://graph.microsoft.com/$graphApiVersion/`$batch"
        try {
            Write-Verbose "Get $batchUri"
            $response = Invoke-RestMethod -Uri $batchUri -Headers $Headers -Method Post -Body $BatchBody
        }
        catch {
            Write-ErrorResponse($_)
        }

        If($Passthru){
            return $response.responses.body
        }
        Else{
            $BatchResponses = @()
            $i=0
            foreach($Element in $response.responses.body){
                $hashtable = @{}
                Foreach($Item in $Element.value){
                    foreach( $property in $Item.psobject.properties.name )
                    {
                        $hashtable[$property] = $Item.$property
                    }
                    $hashtable['uri'] = "https://graph.microsoft.com/$graphApiVersion" + $batch[$i].url
                    $hashtable['type'] = (Split-Path $Element.'@odata.context' -Leaf).replace('$metadata#','')
                    $Object = New-Object PSObject -Property $hashtable
                    $BatchResponses += $Object
                }
                $i++
            }
            return $BatchResponses
        }
    }
}



Function Invoke-IDMGraphRequests{
    <#
    .SYNOPSIS
        Invoke GET method to Microsoft Graph Rest API in multithread

    .DESCRIPTION
        Invoke Rest method using the get method but do it using a pool of runspaces

    .PARAMETER $Uri
        Specify graph uri(s) for requests

    .PARAMETER Headers
        Header for Graph bearer token. Must be in hashtable format:
        Name            Value
        ----            -----
        Authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6ImVhMnZPQjlqSmNDOTExcVJtNE1EaEpCd2YyVmRyNXlodjRqejFOOUZhNmciLCJhbGci...'
        Content-Type = 'application/json'
        ExpiresOn = '7/29/2022 7:55:14 PM +00:00'

        Use command:
        $AuthToken = Get-IDMGraphAuthToken -User (Connect-MSGraph).UPN

    .PARAMETER Threads
        Integer. Defaults to 15. Don't change unless needed (for slower CPU's)

    .PARAMETER Passthru
        Using -Passthru will out graph data including next link and context. Value contains devices.
        No Passthru will out value only

    .EXAMPLE
        $Uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
        Invoke-IDMGraphRequests -Uri $Uri -Headers $AuthToken

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
        $Responses = $Uri | Invoke-IDMGraphRequests -Headers $AuthToken -Threads $Uri.count

    .EXAMPLE
        Invoke-IDMGraphRequests -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Headers $AuthToken -Passthru

    .LINK
        https://b-blog.info/en/implement-multi-threading-with-net-runspaces-in-powershell.html
        https://adamtheautomator.com/powershell-multithreading/

    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,HelpMessage="Specify Uri or array or Uris")]
        [string[]]$Uri,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [int]$Threads = 15,

        [switch]$Passthru
    )
    Begin{
        #initialSessionState will hold typeDatas and functions that will be passed to every runspace.
        $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault();

        #define function to run
        function Get-RestData {
            param (
                [Parameter(Mandatory=$true,Position=0)][string]$Uri,
                [Parameter(Mandatory=$False,Position=1)][hashtable]$Headers
            )
            try {
                $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -DisableKeepAlive -ErrorAction Stop
            } catch {
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Error ("{0}: Error Status: {1}; {2}" -f $uri,$ex.Response.StatusCode,$responseBody)
            }

            return $response
        }

        #add function to the initialSessionState
        $GetRestData_def = Get-Content Function:\Get-RestData
        $GetRestDataSessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList 'Get-RestData', $GetRestData_def
        $initialSessionState.Commands.Add($GetRestDataSessionStateFunction)

        #define your TypeData (Makes the output as object later on)
        $init = @{
            MemberName = 'Init';
            MemberType = 'ScriptMethod';
            Value = {
                Add-Member -InputObject $this -MemberType NoteProperty -Name uri -Value $null
                Add-Member -InputObject $this -MemberType NoteProperty -Name headers -Value $null
                Add-Member -InputObject $this -MemberType NoteProperty -Name rawdata -Value $null
            };
            Force = $true;
        }

        # and initiate the function call to add to session state:
        $populate = @{
            MemberName = 'Populate';
            MemberType = 'ScriptMethod';
            Value = {
                param (
                    [Parameter(Mandatory=$true)][string]$Uri,
                    [Parameter(Mandatory=$true)][hashtable]$Headers
                )
                $this.uri = $Uri
                $this.headers = $Headers
                $this.rawdata = (Get-RestData -Uri $Uri -Headers $Headers)
            };
            Force = $true;
        }

        Update-TypeData -TypeName 'Custom.Object' @Init;
        Update-TypeData -TypeName 'Custom.Object' @Populate;
        $customObject_typeEntry = New-Object System.Management.Automation.Runspaces.SessionStateTypeEntry -ArgumentList $(Get-TypeData Custom.Object), $false;
        $initialSessionState.Types.Add($customObject_typeEntry);

        #define our main, entry point to runspace
        $ScriptBlock = {
            Param (
                [PSCustomObject]$Uri,
                $Headers
            )

            #build object and
            $page = [PsCustomObject]@{PsTypeName ='Custom.Object'};
            $page.Init();
            $page.Populate($Uri,$Headers);

            $Result = New-Object PSObject -Property @{
                uri = $page.Uri
                #value = $page.value
                value = $page.rawdata.value
                nextlink = $page.rawdata.'@odata.nextLink'
            };

            return $Result;
        }

        #build Runsapce threads
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $initialSessionState, $Host);
        $RunspacePool.Open();
        $Jobs = @();
    }
    Process{
        #START THE JOB
        $i = 0;
        foreach($url in $Uri) { #$Uri - some array of uris
            $i++;
            #call scriptblock with arguments
            $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($url).AddArgument($Headers);
            $Job.RunspacePool = $RunspacePool;
            $Jobs += New-Object PSObject -Property @{
                RunNum = $i;
                Pipe = $Job;
                Result = $Job.BeginInvoke();
            }
        }
    }
    End{
        $results = @();
        #TEST $job = $jobs
        foreach ($Job in $Jobs) {
            $Result = $Job.Pipe.EndInvoke($Job.Result)
            #add uri to object list if passthru used
            $Results += $Result
        }

        If($Passthru){
            Return $Results
        }
        Else{
            $JobResponses = @()
            $i=0
            $Item = $Results.value[0]
            Foreach($Item in $Results.value){
                $hashtable = @{}
                foreach( $property in $Item.psobject.properties.name  )
                {
                    $hashtable[$property] = $Item.$property
                }
                $hashtable['uri'] = $Results[$i].uri
                #$hashtable['type'] = $Results[$i].uri | Split-Path -Leaf -ErrorAction SilentlyContinue
                $Object = New-Object PSObject -Property $hashtable
                $JobResponses += $Object
                $i++
            }
            return $JobResponses
        }
    }
}
