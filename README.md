<h2>Send Azure AD Logs to Azure Monitor Logs</h2>
The Azure AD Logs can be automatically sent to Azure Monitor Logs:<br/>
https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics<br/>
https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-logs-overview<br/>
However, when there is a requirement to send AAD Logs from a different tenant, we have to revert to a previously existing strategy.
The strategy presented here creates an Azure Automation Runbook that gets the AAD Logs through an API call and puts them in an Azure Monitor Workspace as a custom table.
<br/>
<h3>Pre-requisites:</h3>
<ul>
<li>Create an App Registration and provide RBAC access to the AAD Graph API. These credentials will be used from Azure Automation.  <br/>
https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-configure-prerequisites-for-reporting-api
<li>Have an Automation Account.
<li>Have a log analytics workspace.
</ul>
<h3>Components:</h3>
<ul>
<li>aadapi.psm1 - Powershell module that implements cmdlets to read AAD Logs and Write to AzMon Logs
<li>aadapi.psd1 - Module Manifest
<li>aad2azmon.ps1 - Powershell Automation Runnbook that leverages the aadapi module to accomplish the task
</ul>
<h3>How to run it:</h3>
<ol>
<li>Meet the pre-requisites
<li>Zip and upload aadapi.psm1 and pds1. <br/>https://docs.microsoft.com/en-us/azure/automation/shared-resources/modules
<li>Modify the parameters in aad2azmon.ps1:<br>
  <table>
    <tr><th>Parameter</th><th>Description</th></tr>
    <tr><td>$ClientID</td><td>Client ID from AAD App Registration</td></tr>
    <tr><td>$ClientSecret</td><td>ClientSecret from AAD App Registration</td></tr>
    <tr><td>$workspaceId</td><td>Azure Monitor Logs (aka Log Analytics) Workspace ID</td></tr>
    <tr><td>$SharedKey</td><td>Azure Monitor Logs Shared Key </td></tr>
     <tr><td>$prefix</td><td>AAD prefix to .onmicrosoft.com </td></tr>
  </table>
<li>Upload or copy paste aad2azmon.ps1 as a Runbook in your Azure Automation Account
<li>Add a Schedule to the Runbook, like every hour
<li>Query AzMon Logs Custom Log named AADAuditApi_CL 
</ol>

<h3>Caveats:</h3>
<ul>
<li>Sign-in logs require AAD Premium
<li>This repository is from code I wrote in 2017.  Using the Automation Run-As account identity instead of an App Registration may be a better implementation.
</ul>




