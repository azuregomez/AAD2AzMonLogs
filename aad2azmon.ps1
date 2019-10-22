$ClientID       = "<fromAppRegistration>"      
$ClientSecret   = "<fromAppRegistration>"
$workspaceId = "<fromAzMonLogsWorkspace>"
$SharedKey = "<fromAzMonLogsWorkspace>"
$prefix = "<fromAAD>"
try {
    import-module aadapi.psm1 -ArgumentList $clientid, $clientsecret, $prefix, $workspaceid, $sharedkey -force -verbose 
    #get-command -module aadapi    
    #show-param
    $hoursAgo = 1
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
	    Publish-OmsLogData $omsjson "AADAuditApi" "AADAudit.activityDate"
	    write-output "Exported $records records from AAD to Log Analytics"    
    }
    else{
        write-output "No records exported"
        
    }
    
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}