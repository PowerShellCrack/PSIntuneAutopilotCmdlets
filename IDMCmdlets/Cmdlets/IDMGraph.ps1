Function New-IDMGraphAuthCert{
    
    <#
    .SYNOPSIS
    Creates a new self-signed certificate for use with Azure Entra app registration.

    .DESCRIPTION
    The function creates a new self-signed certificate for use with Azure Entra app registration.

    .PARAMETER TenantName
    Specifies the tenant name (e.g. contoso.onmicrosoft.com) to use for the certificate.

    .PARAMETER CerOutputPath
    Specifies the path to export the certificate without the private key. Default is C:\Temp\PowerShellGraphCert.cer

    .PARAMETER StoreLocation
    Specifies the cert store location. Default is Cert:\CurrentUser\My

    .PARAMETER ExpirationDate
    Specifies the expiration date of the new certificate. Default is 2 years from the current date.

    .EXAMPLE
    New-IDMGraphAuthCert -TenantName "contoso.onmicrosoft.com" -CerOutputPath "C:\Temp\PowerShellGraphCert.cer" -StoreLocation "Cert:\CurrentUser\My" -ExpirationDate (Get-Date).AddYears(2)
    Creates a new self-signed certificate for use with Azure Entra app registration.

    .NOTES
    REFERENCE: https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#create-a-new-application-secret
    REFERENCE: https://adamtheautomator.com/powershell-graph-api/

    #>
    Param(
        [Parameter(Mandatory = $true)]
        $TenantName,
        
        [Parameter(Mandatory = $false)]
        $CerOutputPath= "$env:Temp\PowerShellGraphCert.cer",
        
        [Parameter(Mandatory = $false)]
        $StoreLocation= "Cert:\CurrentUser\My",
        
        [Parameter(Mandatory = $false)]
        $ExpirationDate= (Get-Date).AddYears(2)
    )
    

    # Splat for readability
    $CreateCertificateSplat = @{
        FriendlyName      = "AzureApp"
        DnsName           = $TenantName
        CertStoreLocation = $StoreLocation
        NotAfter          = $ExpirationDate
        KeyExportPolicy   = "Exportable"
        KeySpec           = "Signature"
        Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        HashAlgorithm     = "SHA256"
    }

    # Create certificate
    $Certificate = New-SelfSignedCertificate @CreateCertificateSplat

    # Get certificate path
    $CertificatePath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint

    # Export certificate without private key
    Export-Certificate -Cert $CertificatePath -FilePath $CerOutputPath | Out-Null
}

Function New-IDMGraphApp{
    <#
    .SYNOPSIS
    Creates a new Azure Entra app registration with the necessary permissions for Intune device management.

    .PARAMETER CloudEnvironment
    Specifies the cloud environment to use. Valid values are Public, USGov, USGovDoD.

    .PARAMETER appNamePrefix
    Specifies the prefix for the app name. The app name will be the prefix plus a random identifier.

    .EXAMPLE
    New-IDMGraphApp -CloudEnvironment Public -appNamePrefix "IntuneDeviceManagerApp"
    Creates a new app registration in the public cloud with the name "IntuneDeviceManagerApp-<random identifier>"

    .LINK
    https://learn.microsoft.com/en-us/powershell/microsoftgraph/app-only?view=graph-powershell-1.0&tabs=azure-portal
    https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in
    https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignments?view=graph-rest-1.0&tabs=powershell#request
    https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-tutorial-deployment-script?tabs=CLI
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Public','Global','USGov','USGovDoD')]
        [string] $CloudEnvironment = 'Global',

        [Parameter(Mandatory = $false)]
        $AppNamePrefix = "IntuneDeviceManagerApp",

        [Parameter(Mandatory = $false)]
        [switch]$AsHashTable
    )
    $ErrorActionPreference = 'Stop'

    #Requires -Modules Microsoft.Graph.Authentication,Microsoft.Graph.Applications

    Switch($CloudEnvironment){
        'Public' {$GraphEnvironment = 'Global'}
        'USGov' { $GraphEnvironment = 'USGov'}
        'USGoDoD' { $GraphEnvironment = 'USGovDoD'}
        default { $GraphEnvironment = 'Global'}
    }

    #Connect to Graph
    Write-Host ("Connecting to Graph...") -ForegroundColor Cyan -NoNewline
    Connect-MgGraph -Environment $GraphEnvironment -Scopes "Application.ReadWrite.All","User.Read" -NoWelcome
    Write-Host ("done") -ForegroundColor Green

    $TenantID = Get-MgContext | Select-Object -ExpandProperty TenantId

    #Set variables for the app
    $startDate = Get-Date
    $endDate = $startDate.AddYears(1)
    $randomIdentifier = (New-Guid).ToString().Substring(0,8)
    $appName = ($AppNamePrefix  + '-' + $randomIdentifier)

    #Get Role id for DeviceManagementConfiguration.ReadWrite.All
    #$GraphResourceId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" #Microsoft Intune PowerShell
    #$GraphResourceId = "14d82eec-204b-4c2f-b7e8-296a70dab67e" #Microsoft Graph PowerShell
    #$GraphResourceId = "0000000a-0000-0000-c000-000000000000" #Microsoft Intune
    $GraphResourceId = "00000003-0000-0000-c000-000000000000" #Microsoft Graph
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$GraphResourceId'"
    #$GraphServicePrincipal = (Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'")
    $Permissions = $GraphServicePrincipal.AppRoles | Where-Object {$_.value -in $script:GraphScopes}

    # Create app registration
    Write-Host ("Creating app registration named: {0}..." -f $appName) -ForegroundColor White -NoNewline
    $app = New-MgApplication -DisplayName $appName -AppRoles $Permissions

    # Azure doesn't always update immediately, make sure app exists before we try to update its config
    $appExists = $false
    while (!$appExists) {
        Write-Host "." -NoNewline -ForegroundColor White
        Start-Sleep -Seconds 2
        $appExists = Get-MgApplication -ApplicationId $app.Id
    }
    Write-Host ("{0}" -f $app.AppId) -ForegroundColor Green


    #Create the client secret
    $PasswordCredentials = @{
        StartDateTime = $startDate
        EndDateTime = $endDate
        DisplayName = ($appNamePrefix + "_" + ($startDate).ToUniversalTime().ToString("yyyyMMdd"))
    }
    Write-Host ("Generating app secret with name: {0}..." -f $PasswordCredentials.DisplayName) -ForegroundColor White -NoNewline
    $ClientSecret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $PasswordCredentials
    #$ClientSecret | Select-Object -ExpandProperty SecretText
    Write-Host ("done: {0}..." -f $ClientSecret.SecretText.Substring(0,7)) -ForegroundColor Green


    Write-Host ("Create corresponding service principal..") -ForegroundColor White -NoNewline
    # Create corresponding service principal
    $appSp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host ("done") -ForegroundColor Green


    #Grant the DeviceManagementConfiguration.ReadWrite.All permisssions to api
    #TEST $Permission = $Permissions[0]
    Foreach($Permission in $Permissions){
        Write-Host ("Granting permissions to app: {0}..." -f $Permission.Value) -ForegroundColor White -NoNewline
        $params = @{
            "PrincipalId" = $appSp.id                       #ObjectID of the enterprise app for my app registration
            "ResourceId" = $GraphServicePrincipal.Id        #ID of graph service principal ID in my tenant
            "AppRoleId" = $Permission.Id                    #ID of the graph role
        }
        $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.id -BodyParameter $params
        Write-Host ("done") -ForegroundColor Green
    }

    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue

    Write-Host ("App registration created!") -ForegroundColor Cyan

    #build object to return
    $appdetails = "" | Select-Object AppId,AppSecret,TenantID,CloudEnvironment
    $appdetails.TenantID = $TenantID
    $appdetails.AppId = $app.AppId
    $appdetails.AppSecret = (ConvertTo-SecureString $ClientSecret.SecretText -AsPlainText -Force)
    $appdetails.CloudEnvironment = $GraphEnvironment

    If($AsHashTable){
        $ht2 = @{}
        $appdetails = $appdetails.psobject.properties | Foreach { $ht2[$_.Name] = $_.Value }
        return $ht2
    }Else{
        return $appdetails
    }
}

Function Update-IDMGraphApp{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$AppId,

        [Parameter(Mandatory = $true)]
        [String]$TenantID,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Public','Global','USGov','USGovDoD')]
        [string]$CloudEnvironment = 'Global',

        [Parameter(Mandatory = $false)]
        [string[]]$Permissions,

        [Parameter(Mandatory = $false)]
        [switch]$NewSecret,

        [Parameter(Mandatory = $false)]
        [switch]$AsHashTable
    )

    $ErrorActionPreference = 'Stop'

    #Requires -Modules Microsoft.Graph.Authentication,Microsoft.Graph.Applications

    Switch($CloudEnvironment){
        'Public' {$GraphEnvironment = 'Global'}
        'USGov' { $GraphEnvironment = 'USGov'}
        'USGoDoD' { $GraphEnvironment = 'USGovDoD'}
        default { $GraphEnvironment = 'Global'}
    }

    #Connect to Graph
    Write-Host ("Connecting to Graph...") -ForegroundColor Cyan -NoNewline
    Connect-MgGraph -Environment $GraphEnvironment -Scopes "Application.ReadWrite.All","User.Read" -NoWelcome
    Write-Host ("done") -ForegroundColor Green

    $TenantID = Get-MgContext | Select-Object -ExpandProperty TenantId
    #Set variables for the app
    $AppServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$AppId'"

    If($AppServicePrincipal){

        $GraphResourceId = "00000003-0000-0000-c000-000000000000" #Microsoft Graph
        $GraphServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$GraphResourceId'"

        Foreach($Permission in $Permissions)
        {
            If($GraphServicePrincipal.AppRoles | Where-Object {$_.value -eq $Permission})
            {
                If($AppServicePrincipal.AppRoles | Where-Object {$_.value -eq $Permission})
                {
                    Write-Host ("Permission already granted: {0}" -f $Permission) -ForegroundColor Yellow

                }Else{
                    $PermissionScope = $GraphServicePrincipal.AppRoles | Where-Object {$_.value -in $Permission}

                    Write-Host ("Granting permissions to app: {0}..." -f $Permission) -ForegroundColor White -NoNewline
                    $params = @{
                        "PrincipalId" = $AppServicePrincipal.id      #ObjectID of the enterprise app for my app registration
                        "ResourceId" = $GraphServicePrincipal.id     #ID of graph service principal ID in my tenant
                        "AppRoleId" = $PermissionScope.Id             #ID of the graph role
                    }
                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppServicePrincipal.id -BodyParameter $params
                    Write-Host ("done") -ForegroundColor Green
                }
            }Else{
                Write-Host ("Permission not found: {0}" -f $Permission) -ForegroundColor Yellow
            }

        }

        If($NewSecret){
            $AppEnterpriseApplication = Get-MgApplication -Filter "AppId eq '$AppId'"
            #Create the client secret
            $startDate = Get-Date
            $endDate = $startDate.AddYears(1)

            $PasswordCredentials = @{
                StartDateTime = $startDate
                EndDateTime = $endDate
                DisplayName = ($AppServicePrincipal.DisplayName.Split('-')[0] + "_" + ($startDate).ToUniversalTime().ToString("yyyyMMdd"))
            }
            Write-Host ("Generating app secret with name: {0}..." -f $PasswordCredentials.DisplayName) -ForegroundColor White -NoNewline
            $ClientSecret = Add-MgApplicationPassword -ApplicationId $AppEnterpriseApplication.Id -PasswordCredential $PasswordCredentials
            Write-Host ("done: {0}..." -f $ClientSecret.SecretText.Substring(0,7)) -ForegroundColor Green
        }

        $null = Disconnect-MgGraph -ErrorAction SilentlyContinue

        #build object to return
        $appdetails = "" | Select-Object AppId,AppSecret,TenantID,CloudEnvironment
        $appdetails.TenantID = $TenantID
        $appdetails.AppId = $AppServicePrincipal.AppId
        $appdetails.AppSecret = (ConvertTo-SecureString $ClientSecret.SecretText -AsPlainText -Force)
        $appdetails.CloudEnvironment = $GraphEnvironment

        If($AsHashTable){
            $ht2 = @{}
            $appdetails = $appdetails.psobject.properties | Foreach { $ht2[$_.Name] = $_.Value }
            return $ht2
        }Else{
            return $appdetails
        }
        Write-Host ("App registration updated!") -ForegroundColor Cyan

    }else {
        Write-Error ("Appid not found [{0}]. Run New-IDMGraphApp or specifiy a different AppId" -f $AppId)
    }
}

Function Add-IDMGraphAppCertAuth{

    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Public','Global','USGov','USGovDoD')]
        [string] $CloudEnvironment = 'Global',

        [Parameter(Mandatory = $true)]
        $TenantName,

        [Parameter(Mandatory = $true)]
        $AppId,

        [Parameter(Mandatory = $true)]
        $CertificateThumbprint,

        [Parameter(Mandatory = $false)]
        $StoreLocation= "Cert:\CurrentUser\My"
    )
    
    switch ($CloudEnvironment) {
        'Global' {$AzureEndpoint = 'https://login.microsoftonline.com';$graphEndpoint = 'https://graph.microsoft.com'}
        'USGov' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://graph.microsoft.us'}
        'USGovDoD' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://dod-graph.microsoft.us'}
        default {$AzureEndpoint = 'https://login.microsoftonline.com';$graphEndpoint = 'https://graph.microsoft.com'}
    }

    $Scope = "$graphEndpoint/.default"

    $Certificate = Get-Item "$StoreLocation\$CertificateThumbprint"
    # Create base64 hash of certificate
    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

    # Create JWT timestamp for expiration
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

    # Create JWT validity start timestamp
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

    # Create JWT header
    $JWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
        x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    }

    # Create JWT payload
    $JWTPayLoad = @{
        # What endpoint is allowed to use this JWT
        aud = "$AzureEndpoint/$TenantName/oauth2/token"

        # Expiration timestamp
        exp = $JWTExpiration

        # Issuer = your application
        iss = $AppId

        # JWT ID: random guid
        jti = [guid]::NewGuid()

        # Not to be used before
        nbf = $NotBefore

        # JWT Subject
        sub = $AppId
    }

    # Convert header and payload to base64
    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

    $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

    # Join header and Payload with "." to create a valid (unsigned) JWT
    $JWT = $EncodedHeader + "." + $EncodedPayload

    # Get the private key object of your certificate
    $PrivateKey = $Certificate.PrivateKey

    # Define RSA signature and hashing algorithm
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

    # Create a signature of the JWT
    $Signature = [Convert]::ToBase64String(
        $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
    ) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $JWT = $JWT + "." + $Signature

    # Create a hash with body parameters
    $Body = @{
        client_id = $AppId
        client_assertion = $JWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope = $Scope
        grant_type = "client_credentials"

    }

    $Url = "$AzureEndpoint/$TenantName/oauth2/v2.0/token"

    # Use the self-generated JWT as Authorization
    $Header = @{
        Authorization = "Bearer $JWT"
    }

    # Splat the parameters for Invoke-Restmethod for cleaner code
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $Body
        Uri = $Url
        Headers = $Header
    }

    $Request = Invoke-RestMethod @PostSplat

    return $Request
}
Function Get-IDMGraphAppAuthToken {
    <#
    .SYNOPSIS
    Authenticates to the Graph API via the Microsoft.Graph.Intune module using app-based authentication.

    .DESCRIPTION
    The Connect-IDMGraphApp cmdlet is a wrapper cmdlet that helps authenticate to the Graph API using the Microsoft.Graph.Intune module.
    It leverages an Azure Entra app ID and app secret for authentication. See https://oofhours.com/2019/11/29/app-based-authentication-with-intune/ for more information.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#create-a-new-application-secret

    .PARAMETER Tenant
    Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

    .PARAMETER AppId
    Specifies the Azure Entra app ID (GUID) for the application that will be used to authenticate.

    .PARAMETER AppSecret
    Specifies the Azure Entra app secret corresponding to the app ID that will be used to authenticate.

    .PARAMETER AESKey
    Specifies the AES key used to encrypt the app secret. This is required if the app secret is encrypted.

    .EXAMPLE
    $app = New-IDMGraphApp -CloudEnvironment Public -appNamePrefix "IntuneDeviceManagerApp" -AsHashTable
    $token = Get-IDMGraphAppAuthToken @app -ReturnToken
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Public','Global','USGov','USGovDoD')]
        [string] $CloudEnvironment = 'Global',

        [Parameter(Mandatory=$true)]
        [Alias('ClientId')]
        [String]$AppId,

        [Parameter(Mandatory=$true)]
        [Alias('Tenant')]
        [String]$TenantID,

        [Parameter(Mandatory=$true)]
        [Alias('ClientSecret')]
        $AppSecret,

        [Parameter(Mandatory = $false)]
        [string[]]$AESKey,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnToken
    )

    switch ($CloudEnvironment) {
        'Global' {$AzureEndpoint = 'https://login.microsoftonline.com';$graphEndpoint = 'https://graph.microsoft.com'}
        'USGov' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://graph.microsoft.us'}
        'USGovDoD' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://dod-graph.microsoft.us'}
        default {$AzureEndpoint = 'https://login.microsoftonline.com';$graphEndpoint = 'https://graph.microsoft.com'}
    }

    If($AESKey){
        $AppSecret = $AppSecret | ConvertTo-SecureString -Key $AESKey
        $SecureStringParams = @{
            Key = $AESKey
            AsPlainText = $true
        }
    }Else{
        $SecureStringParams = @{
            AsPlainText = $true
        }
    }

    try {

        $Body = @{
            Grant_Type    = "client_credentials"
            Scope         = "$graphEndpoint/.default"
            client_Id     = $AppId
            Client_Secret = ($AppSecret | ConvertFrom-SecureString @SecureStringParams)
        }
        $ConnectGraph = Invoke-RestMethod -Uri "$AzureEndpoint/$TenantID/oauth2/v2.0/token" -Method POST -Body $Body -ErrorAction Stop
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
    }
    Catch{
        Write-Error ("{0}: {1}" -f $_.Exception.ItemName, $_.Exception.Message)
    }

    If($ReturnToken){
        return $token
    }
    else{
        return $authHeader
    }
}

function Connect-IDMGraphApp{

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

    .EXAMPLE
        Get-IDMGraphAuthToken -cloudEnvironment USGov -AppAuthToken $Token
        Authenticates you with the Graph API interface using the app token

    .NOTES
    Requires: Microsoft.Graph.Authentication module

    .LINK
    Reference: https://learn.microsoft.com/en-us/graph/deployments

    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Global','USGov','USGovDoD')]
        [string] $CloudEnvironment = 'Global',

        [Parameter(Mandatory = $false)]
        $AppAuthToken
    )

    If($AppAuthToken)
    {
        #retrieve token and secure it
        If($AppAuthToken.Authorization){
            $SecureToken = ConvertTo-SecureString ($AppAuthToken.Authorization.Replace('Bearer','').Trim()) -AsPlainText -Force
        }Else{
            $SecureToken = ConvertTo-SecureString $AppAuthToken -AsPlainText -Force
        }

        Try{
            Connect-MgGraph -Environment $CloudEnvironment -AccessToken $SecureToken -NoWelcome
        }
        Catch{
            Write-Error ("{0}: {1}" -f $_.Exception.ItemName, $_.Exception.Message)
        }

    }Else{

        Try{
            Connect-MgGraph -Environment $CloudEnvironment -Scopes $script:GraphScopes -NoWelcome
        }
        Catch{
            Write-Error ("{0}: {1}" -f $_.Exception.ItemName, $_.Exception.Message)
        }

    }

    $context = Get-MgContext

    #Set global variable for graph endpoint
    switch ($context.Environment) {
        'Global' {$Global:GraphEndpoint = 'https://graph.microsoft.com'}
        'USGov' {$Global:GraphEndpoint = 'https://graph.microsoft.us'}
        'USGovDoD' {$Global:GraphEndpoint = 'https://dod-graph.microsoft.us'}
        default {$Global:GraphEndpoint = 'https://graph.microsoft.com'}
    }

    return $context
}

function Update-IDMGraphAppAuthToken{
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
        Reference: https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud
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

        [Parameter(Mandatory = $false)]
        [ValidateSet('Global','USGov','USGovDoD')]
        [string] $CloudEnvironment = 'Global',

        [parameter(Mandatory = $false)]
        [String[]]$Scope = @("Group.ReadWrite.All","User.ReadWrite.All")
    )

    # Defining graph variables
    $oAuthApiVersion = "v2.0"

    switch ($CloudEnvironment) {
        'Global' {$AzureEndpoint = 'https://login.microsoftonline.com';$graphEndpoint = 'https://graph.microsoft.com'}
        'USGov' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://graph.microsoft.us'}
        'USGovDoD' {$AzureEndpoint = 'https://login.microsoftonline.us';$graphEndpoint = 'https://dod-graph.microsoft.us'}
    }

    $uri = "$AzureEndpoint/$TenantID/oauth2/$oAuthApiVersion/token"

    $bodyHash = @{
        client_id = $ClientID
        scope = ($Scope -join ' ')
        refresh_token = $Token
        #redirect_uri =' http://localhost'
        redirect_uri = ($graphEndpoint + '/.default')
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

    #$PSDefaultParameterValues['Invoke-MgGraphRequest:Headers'] = $Response
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
            'https://graph.microsoft.com/beta/users/79e27b13-bf4d-47d9-a820-5ee8955fcfb4/memberOf'
            'https://graph.microsoft.com/beta/devices/09692e55-e52c-465b-b2dd-a4e9ed77c428/memberOf'
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
        $uri = $UriResources
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
        [hashtable]$Headers,

        [switch]$Passthru
    )
    Begin{
        $graphApiVersion = "beta"
        $Method = 'GET'
        $batch = @()
        $i = 1
        #Build custom object for assignment
        $BatchProperties = "" | Select requests
        If(-Not(Get-MgContext)){
            Write-Error "Graph endpoint not found. Please authenticate with Get-IDMGraphAuthToken or Connect-MgGraph first"
        }
    }
    Process{

        Foreach($url in $Uri | Select -Unique)
        {
            $URLRequests = "" | Select id,method,url
            $URLRequests.id = $i
            $URLRequests.method = $Method
            $URLRequests.url = $url.replace("$Global:GraphEndpoint/$graphApiVersion",'')
            $i++
            $batch += $URLRequests
        }

    }
    End{
        $BatchProperties.requests = $batch
        #convert body to json
        $BatchBody = $BatchProperties | ConvertTo-Json
        Write-Verbose $BatchBody

        $RestParams = @{
            Uri = "$Global:GraphEndpoint/$graphApiVersion/`$batch"
            Method = 'Post'
            Body = $BatchBody
        }

        If($Headers){
            $RestParams += @{
                Headers = $Headers
            }
        }

        try {
            Write-Verbose "Get $batchUri"
            #$Responses = Invoke-RestMethod -Uri $batchUri -Headers $Headers -Method Post -Body $BatchBody
            $Responses = (Invoke-MgGraphRequest @RestParams -ErrorAction Stop).responses
        }
        catch {
            Write-ErrorResponse($_)
        }

        
        If($Passthru){
            #return raw results (including uri, value, next link)
            Return $Responses
        }
        Else{

            $BatchResponses = @()
            #$i= 0
            #TEST = ($bodyValue = $Responses.body[0]).Value
            foreach($body in $Responses.body)
            {
                If($null -ne $body.Value){
                    $BatchResponses += ConvertFrom-GraphHashtable -GraphData $body.Value `
                                            -ResourceUri ($body.'@odata.context'.replace('$metadata#',''))
                }
                
                #$i++
            }

            return $BatchResponses
        }

        <#
        If($Passthru){
            return $Responses
        }
        Else{
            $BatchResponses = @()
            $i=0
            foreach($Element in $Response.body){
                $hashtable = @{}
                Foreach($Item in $Element.value){
                    foreach( $property in $Item.psobject.properties.name )
                    {
                        $hashtable[$property] = $Item.$property
                    }
                    $hashtable['uri'] = "$Global:GraphEndpoint/$graphApiVersion/" + $Item[$i].url + '/' + $Item.id
                    #$hashtable['type'] = (Split-Path $Element.'@odata.context' -Leaf).replace('$metadata#','')
                    $Object = New-Object PSObject -Property $hashtable
                    $BatchResponses += $Object
                }
                $i++
            }
            return $BatchResponses
        }
         #>
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
        Using -Passthru will out graph data including next link and context. Value property contains results.
        No Passthru will out value only

    .EXAMPLE
        $Uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
        Invoke-IDMGraphRequests -Uri $Uri

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
        $Responses = $Uri | Invoke-IDMGraphRequests -Threads $Uri.count -passthru

    .EXAMPLE
        Invoke-IDMGraphRequests -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Passthru
        Invoke-IDMGraphRequests -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags' -Passthru

    .LINK
        https://b-blog.info/en/implement-multi-threading-with-net-runspaces-in-powershell.html
        https://adamtheautomator.com/powershell-multithreading/

    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,HelpMessage="Specify Uri or array or Uris")]
        [string[]]$Uri,

        [Parameter(Mandatory=$false)]
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

            $RestParams = @{
                Uri = $Uri
                Method = 'Get'
            }

            If($Headers){
                $RestParams += @{
                    Headers = $Headers
                }
            }

            try {
                #$response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -DisableKeepAlive -ErrorAction Stop
                $response = Invoke-MgGraphRequest @RestParams -ErrorAction Stop
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

        #TEST $populate.Value
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
            #return raw results (including uri, value, next link)
            Return $Results
        }
        Else{
            #build object to return with combined uri and value
            $Responses = @()
            #$i=0

            foreach($item in $Results){
                $Responses += ConvertFrom-GraphHashtable -GraphData $item.Value -ResourceUri ($item.uri)
                #$i++
            }
            <#
            #loop through each uri
            Foreach($uri in $Results.uri){
                #loop through each item to build object
                #TEST $Item = $Results.value[0]
                Foreach($item in $Results.value){
                    $hashtable = @{}
                    #TEST $property = $item.GetEnumerator() | select -first 1
                    foreach( $property in $item.GetEnumerator() )
                    {
                        $hashtable[$property.Name] = $property.Value
                    }
                    $hashtable['uri'] = ($Results[$i].uri + '/' + $item.id)
                    #convert hashtable to object
                    $Object = New-Object PSObject -Property $hashtable
                    $Responses += $Object
                }
                $i++
            }
            #>

            return $Responses
        }
    }
}