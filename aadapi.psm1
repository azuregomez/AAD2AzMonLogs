<#
    .SYNOPSIS
     Gets Get AAD Audit Logs into OMS Log Analytics 
	 
	 .DESCRIPTION
        1. Gets ADD Log Audit Information: https://docs.microsoft.com/en-us/azure/active-directory/active-directory-reporting-activity-audit-logs
		2. Flattens the json using https://github.com/RamblingCookieMonster/PowerShell/blob/master/ConvertTo-FlatObject.ps1
		3. Logs it to OMS Log Analytics: https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api

    .PARAMETER ClientID
        ApplicationID https://docs.microsoft.com/en-us/azure/active-directory/active-directory-reporting-api-prerequisites-azure-portal
		
	.PARAMETER ClientSecret
		From AAD Application Keys blade
		
	.PARAMETER tenantdomainprefix
		AAD domain prefix like <tenantdomainprefix>.onmicrosoft.com
		
	.PARAMETER WorkspaceId
		OMS Workspace ID
		
	.PARAMETER SharedKey
		OMS Workspace Primary Key. From OMS Portal > Settings > Connected Sources
#>


param(
    [parameter(Position=0,Mandatory=$true)][string]$ClientID,
    [parameter(Position=1,Mandatory=$true)][string]$ClientSecret,
	[parameter(Position=2,Mandatory=$true)][string]$tenantdomainprefix,
	[parameter(Position=3,Mandatory=$true)][string]$WorkspaceId,
	[parameter(Position=4,Mandatory=$true)][string]$SharedKey

)


function Show-Param {
	Write-Output "Client ID: $ClientID"
	Write-Output "ClientSecret: $ClientSecret"
	Write-Output "Tenant: $tenantdomainprefix"
	Write-Output "Workspace ID: $WorkspaceId"
	Write-Output "SharedKey: $SharedKey"	
}

# region  Functions that get data from AAD  

function Get-Audit {

	param(
		[parameter(Position=0,Mandatory=$true)][int32]$hoursAgo
	)

	#$ClientID       = #from parameters
	#$ClientSecret   = #from parameters
	$tenantdomain   = $tenantdomainprefix + ".onmicrosoft.com"    # AAD Tenant; for example, contoso.onmicrosoft.com	
	#write-output "Tenant Domain $tenantdomain"
	$loginURL       = "https://login.microsoftonline.com"     # AAD Instance; for example https://login.microsoftonline.com	
	$resource       = "https://graph.windows.net"             # Azure AD Graph API resource URI
	$nhoursago       = "{0:s}" -f (get-date).AddHours(-$hoursAgo) + "Z" 
	
	# Create HTTP header, get an OAuth2 access token based on client id, secret and tenant domain
	$body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
	#Write-Output "DEBUG: OAuth request body: $body"
	$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body	
	# Parse audit report items, save output to file(s): auditX.json, where X = 0 thru n for number of nextLink pages
	if ($oauth.access_token -ne $null) {   
		#Write-Output "Querying actvitydate gt $nhoursago"
		$i=0
		$headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
		$url = 'https://graph.windows.net/' + $tenantdomain + '/activities/audit?api-version=beta&$filter=activityDate gt ' + $nhoursago			
		#Write-Output "URL: $url"
		$thelist = @()
		# loop through each query page (1 through n)
		Do{
			# display each event on the console window
			# Write-Output "Fetching data using Uri: $url"
			$myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
			foreach ($event in ($myReport.Content | ConvertFrom-Json).value) {				
				#$thelist+= ($event | ConvertTo-Json)	
				$thelist+= $event
			}
			# save the query page to an output file
			#Write-Output "Save the output to a file audit$i.json"
			#$myReport.Content | Out-File -FilePath audit$i.json -Force
			$url = ($myReport.Content | ConvertFrom-Json).'@odata.nextLink'
			$i = $i+1
		} while($url -ne $null)
	} 
	else {
		Write-Output "ERROR: No Access Token"
	}
	return $thelist

}

#endregion

# region Functions that send data to OMS

# Create authorization signature
Function New-OmsSignature ($date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId,$encodedHash
    return $authorization
}



# post request
Function Publish-OmsLogData($json, $logType, $TimeStampField)
{
	$body = [System.Text.Encoding]::UTF8.GetBytes($json)
	
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $thedate = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = New-OmsSignature -date $thedate -contentLength $contentLength -method $method -contentType $contentType -resource $resource
	$stringuri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $uri = [System.Uri]$stringuri
	
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $thedate;
        "time-generated-field" = $TimeStampField;
    }	
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

#endregion

# region  Function that takes from AAD and sends to OmsLogData

function Import-AADAuditToOMS($hoursAgo){    		
    write-output "Querying AAD for events from $hoursAgo hours ago"
	$list = get-audit $hoursAgo		 
    $records = $list.length
	write-output "AAD returned $records records"
    if($list.length -gt 0){
        write-output $list | format-table      
        # flatten it:
	    $objlistflat = $list | convertto-flatobject		
        # back to json
	    $omsjson = $objlistflat | convertto-json
	    Publish-OmsLogData $omsjson "AADApiAudit" "AADAudit.activityDate"
	    write-output "Exported $records records from AAD to Log Analytics"    
    }
    else{
        write-output "No records exported"
        
    }
}

# This is just a test/debug function that logs a message
function Push-Message($message, $logType){
	$thedate = "{0:s}" -f (get-date) + "Z"     
	$request = new-object psobject -property @{ 
		"Message" = $message   
		"DateValue"= $thedate
	} | convertto-json 
	Publish-OmsLogData $request $logType "DateValue"
}

#endregion

#region Convert To FlatObject 

# from https://github.com/RamblingCookieMonster/PowerShell/blob/master/ConvertTo-FlatObject.ps1


Function ConvertTo-FlatObject {
    <#
    .SYNOPSIS
        Flatten an object to simplify discovery of data

    .DESCRIPTION
        Flatten an object.  This function will take an object, and flatten the properties using their full path into a single object with one layer of properties.

        You can use this to flatten XML, JSON, and other arbitrary objects.

        This can simplify initial exploration and discovery of data returned by APIs, interfaces, and other technologies.

        NOTE:
            Use tools like Get-Member, Select-Object, and Show-Object to further explore objects.
            This function does not handle certain data types well.  It was original designed to expand XML and JSON.

    .PARAMETER InputObject
        Object to flatten

    .PARAMETER Exclude
        Exclude any nodes in this list.  Accepts wildcards.

        Example:
            -Exclude price, title

    .PARAMETER ExcludeDefault
        Exclude default properties for sub objects.  True by default.

        This simplifies views of many objects (e.g. XML) but may exclude data for others (e.g. if flattening a process, ProcessThread properties will be excluded)

    .PARAMETER Include
        Include only leaves in this list.  Accepts wildcards.

        Example:
            -Include Author, Title

    .PARAMETER Value
        Include only leaves with values like these arguments.  Accepts wildcards.

    .PARAMETER MaxDepth
        Stop recursion at this depth.

    .INPUTS
        Any object

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .EXAMPLE

        #Pull unanswered PowerShell questions from StackExchange, Flatten the data to date a feel for the schema
        Invoke-RestMethod "https://api.stackexchange.com/2.0/questions/unanswered?order=desc&sort=activity&tagged=powershell&pagesize=10&site=stackoverflow" |
            ConvertTo-FlatObject -Include Title, Link, View_Count

            $object.items[0].owner.link : http://stackoverflow.com/users/1946412/julealgon
            $object.items[0].view_count : 7
            $object.items[0].link       : http://stackoverflow.com/questions/26910789/is-it-possible-to-reuse-a-param-block-across-multiple-functions
            $object.items[0].title      : Is it possible to reuse a &#39;param&#39; block across multiple functions?
            $object.items[1].owner.link : http://stackoverflow.com/users/4248278/nitin-tyagi
            $object.items[1].view_count : 8
            $object.items[1].link       : http://stackoverflow.com/questions/26909879/use-powershell-to-retreive-activated-features-for-sharepoint-2010
            $object.items[1].title      : Use powershell to retreive Activated features for sharepoint 2010
            ...

    .EXAMPLE

        #Set up some XML to work with
        $object = [xml]'
            <catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>'

        #Call the flatten command against this XML
            ConvertTo-FlatObject $object -Include Author, Title, Price

            #Result is a flattened object with the full path to the node, using $object as the root.
            #Only leaf properties we specified are included (author,title,price)

                $object.catalog.book[0].author : Gambardella, Matthew
                $object.catalog.book[0].title  : XML Developers Guide
                $object.catalog.book[0].price  : 44.95
                $object.catalog.book[1].author : Ralls, Kim
                $object.catalog.book[1].title  : Midnight Rain
                $object.catalog.book[1].price  : 5.95

        #Invoking the property names should return their data if the orginal object is in $object:
            $object.catalog.book[1].price
                5.95

            $object.catalog.book[0].title
                XML Developers Guide

    .EXAMPLE

        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -exclude price, title, id

        Result is a flattened object with the full path to the node, using XML as the root.  Price and title are excluded.

            $Object.catalog                : catalog
            $Object.catalog.book           : {book, book}
            $object.catalog.book[0].author : Gambardella, Matthew
            $object.catalog.book[0].genre  : Computer
            $object.catalog.book[1].author : Ralls, Kim
            $object.catalog.book[1].genre  : Fantasy

    .EXAMPLE
        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -Value XML*, Fantasy

        Result is a flattened object filtered by leaves that matched XML* or Fantasy

            $Object.catalog.book[0].title : XML Developers Guide
            $Object.catalog.book[1].genre : Fantasy

    .EXAMPLE
        #Get a single process with all props, flatten this object.  Don't exclude default properties
        Get-Process | select -first 1 -skip 10 -Property * | ConvertTo-FlatObject -ExcludeDefault $false

        #NOTE - There will likely be bugs for certain complex objects like this.
                For example, $Object.StartInfo.Verbs.SyncRoot.SyncRoot... will loop until we hit MaxDepth. (Note: SyncRoot is now addressed individually)

    .NOTES
        I have trouble with algorithms.  If you have a better way to handle this, please let me know!

    .FUNCTIONALITY
        General Command
    #>
    [cmdletbinding()]
    param(

        [parameter( Mandatory = $True,
                    ValueFromPipeline = $True)]
        [PSObject[]]$InputObject,

        [string[]]$Exclude = "",

        [bool]$ExcludeDefault = $True,

        [string[]]$Include = $null,

        [string[]]$Value = $null,

        [int]$MaxDepth = 10
    )
    Begin
    {
        #region FUNCTIONS

            #Before adding a property, verify that it matches a Like comparison to strings in $Include...
            Function IsIn-Include {
                param($prop)
                if(-not $Include) {$True}
                else {
                    foreach($Inc in $Include)
                    {
                        if($Prop -like $Inc)
                        {
                            $True
                        }
                    }
                }
            }

            #Before adding a value, verify that it matches a Like comparison to strings in $Value...
            Function IsIn-Value {
                param($val)
                if(-not $Value) {$True}
                else {
                    foreach($string in $Value)
                    {
                        if($val -like $string)
                        {
                            $True
                        }
                    }
                }
            }

            Function Get-Exclude {
                [cmdletbinding()]
                param($obj)

                #Exclude default props if specified, and anything the user specified.  Thanks to Jaykul for the hint on [type]!
                    if($ExcludeDefault)
                    {
                        Try
                        {
                            $DefaultTypeProps = @( $obj.gettype().GetProperties() | Select -ExpandProperty Name -ErrorAction Stop )
                            if($DefaultTypeProps.count -gt 0)
                            {
                                Write-Verbose "Excluding default properties for $($obj.gettype().Fullname):`n$($DefaultTypeProps | Out-String)"
                            }
                        }
                        Catch
                        {
                            Write-Verbose "Failed to extract properties from $($obj.gettype().Fullname): $_"
                            $DefaultTypeProps = @()
                        }
                    }

                    @( $Exclude + $DefaultTypeProps ) | Select -Unique
            }

            #Function to recurse the Object, add properties to object
            Function Recurse-Object {
                [cmdletbinding()]
                param(
                    $Object,
                    [string[]]$path = 'AADAudit',   # ********************  I changed this so the entries have AADAudit prefix in OMS - egomez
                    [psobject]$Output,
                    $depth = 0
                )

                # Handle initial call
                    Write-Verbose "Working in path $Path at depth $depth"
                    Write-Debug "Recurse Object called with PSBoundParameters:`n$($PSBoundParameters | Out-String)"
                    $Depth++

                #Exclude default props if specified, and anything the user specified.
                    $ExcludeProps = @( Get-Exclude $object )

                #Get the children we care about, and their names
                    $Children = $object.psobject.properties | Where {$ExcludeProps -notcontains $_.Name }
                    Write-Debug "Working on properties:`n$($Children | select -ExpandProperty Name | Out-String)"

                #Loop through the children properties.
                foreach($Child in @($Children))
                {
                    $ChildName = $Child.Name
                    $ChildValue = $Child.Value

                    Write-Debug "Working on property $ChildName with value $($ChildValue | Out-String)"
                    # Handle special characters...
                        if($ChildName -match '[^a-zA-Z0-9_]')
                        {
                            $FriendlyChildName = "'$ChildName'"
                        }
                        else
                        {
                            $FriendlyChildName = $ChildName
                        }

                    #Add the property.
                        if((IsIn-Include $ChildName) -and (IsIn-Value $ChildValue) -and $Depth -le $MaxDepth)
                        {
                            $ThisPath = @( $Path + $FriendlyChildName ) -join "."
                            $Output | Add-Member -MemberType NoteProperty -Name $ThisPath -Value $ChildValue
                            Write-Verbose "Adding member '$ThisPath'"
                        }

                    #Handle null...
                        if($ChildValue -eq $null)
                        {
                            Write-Verbose "Skipping NULL $ChildName"
                            continue
                        }

                    #Handle evil looping.  Will likely need to expand this.  Any thoughts on a better approach?
                        if(
                            (
                                $ChildValue.GetType() -eq $Object.GetType() -and
                                $ChildValue -is [datetime]
                            ) -or
                            (
                                $ChildName -eq "SyncRoot" -and
                                -not $ChildValue
                            )
                        )
                        {
                            Write-Verbose "Skipping $ChildName with type $($ChildValue.GetType().fullname)"
                            continue
                        }

                    #Check for arrays
                        $IsArray = @($ChildValue).count -gt 1
                        $count = 0

                    #Set up the path to this node and the data...
                        $CurrentPath = @( $Path + $FriendlyChildName ) -join "."

                    #Exclude default props if specified, and anything the user specified.
                        $ExcludeProps = @( Get-Exclude $ChildValue )

                    #Get the children's children we care about, and their names.  Also look for signs of a hashtable like type
                        $ChildrensChildren = $ChildValue.psobject.properties | Where {$ExcludeProps -notcontains $_.Name }
                        $HashKeys = if($ChildValue.Keys -notlike $null -and $ChildValue.Values)
                        {
                            $ChildValue.Keys
                        }
                        else
                        {
                            $null
                        }
                        Write-Debug "Found children's children $($ChildrensChildren | select -ExpandProperty Name | Out-String)"

                    #If we aren't at max depth or a leaf...
                    if(
                        (@($ChildrensChildren).count -ne 0 -or $HashKeys) -and
                        $Depth -lt $MaxDepth
                    )
                    {
                        #This handles hashtables.  But it won't recurse...
                            if($HashKeys)
                            {
                                Write-Verbose "Working on hashtable $CurrentPath"
                                foreach($key in $HashKeys)
                                {
                                    Write-Verbose "Adding value from hashtable $CurrentPath['$key']"
                                    $Output | Add-Member -MemberType NoteProperty -name "$CurrentPath['$key']" -value $ChildValue["$key"]
                                    $Output = Recurse-Object -Object $ChildValue["$key"] -Path "$CurrentPath['$key']" -Output $Output -depth $depth
                                }
                            }
                        #Sub children?  Recurse!
                            else
                            {
                                if($IsArray)
                                {
                                    foreach($item in @($ChildValue))
                                    {
                                        Write-Verbose "Recursing through array node '$CurrentPath'"
                                        $Output = Recurse-Object -Object $item -Path "$CurrentPath[$count]" -Output $Output -depth $depth
                                        $Count++
                                    }
                                }
                                else
                                {
                                    Write-Verbose "Recursing through node '$CurrentPath'"
                                    $Output = Recurse-Object -Object $ChildValue -Path $CurrentPath -Output $Output -depth $depth
                                }
                            }
                        }
                    }

                $Output
            }

        #endregion FUNCTIONS
    }
    Process
    {
        Foreach($Object in $InputObject)
        {
            #Flatten the XML and write it to the pipeline
                Recurse-Object -Object $Object -Output $( New-Object -TypeName PSObject )
        }
    }
}

#endregion

export-modulemember -function Import-AADAuditToOMS 
export-modulemember -function Show-Param
export-modulemember -function Push-Message
export-modulemember -function Publish-OmsLogData
export-modulemember -function Import-AADAuditToOMS
export-modulemember -function Get-Audit
export-modulemember -function ConvertTo-FlatObject
