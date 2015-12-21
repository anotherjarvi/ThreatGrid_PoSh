<# 	   .SYNOPSIS
        These functions connect to ThreatGrid private/public cloud appliances and return various details including samples' submission metrics
		i.e.: runtime, threat score, and file hash.
	   .DESCRIPTION
	    
	   .PARAMETER
		none
       .INPUTS
	   .VERSION
	    v1.0
		This is a very simple first offering that provides a good example of interacting with the TG API.
		See the TG API documentation for other namespaces and key/pair search options.
	   .OUTPUTS
	    csv to PS Object Array (Object[])
	   .NOTES
        Name: ThreatGrid.psm1
        Author: Steve Jarvi
        DateCreated: 21 Dec 2015
		You will need to have set up your account and retrieved your API key.
	   .EXAMPLE
	    $results = Get-BasicTGMetrics "MyTGAppliance.org.com" "XXXXXXXXXXXXXXXXXXXXXXXXXX"
    #>



Function Get-BasicTGSubmissionsMetrics {
<#
This function queries the "Submissions" namespace:
<GET /search/submissions>
#>

param (
[string]$ApplianceName,
[string]$apikey
)


<#
Using Invoke-RestMethod fails because these certificates are untrusted.
The following temporarily trusts all certificates for this session.
#>


add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


$url = "https://$applianceName`:443/api/v2/search/submissions?"
$results = Invoke-RestMethod -uri $url -Method "Get" -body @{"api_key"= $apikey;"path"="%";"sort_by"="duration";"limit"="100000"}

[string]$csvstring = "Sample`tMD5`tSubmitted`tFilename`tState`tRuntime in Minutes`tThreat Score`tThreat Name`n"

	
	
	foreach ($submission in $results.data.items) {
		
		$sample = $submission.item.sample
		$MD5 = $submission.item.MD5
		$Submitted = $submission.item.submitted_at
		$Filename = $submission.item.filename
		$State = $submission.item.state
		$Runtime = ( ([math]::Round($submission.item.analysis.metadata.sandcastle_env.run_time/60,2)))
		$ThreatScore = $submission.item.analysis.threat_score
		$ThreatName = $submission.item.analysis.behaviors.name
		
		[string]$csvstring += $sample + "`t" + $MD5 + "`t" + $Submitted + "`t" + $Filename + "`t" + $State + "`t" + $Runtime + "`t" + $ThreatScore + "`t" + $ThreatName + "`t`n"
	
	}

return $csvstring | convertfrom-csv

}