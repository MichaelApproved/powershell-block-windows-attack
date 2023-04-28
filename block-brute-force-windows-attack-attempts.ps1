#Checks for IP addresses that used incorrect password more than '$blockCount' times
#within '$lastHour' hours and blocks them using a firewall rule 'BlockAttackers'
#'BlockAttackers' required to create manually

$logPath = '.\blocked.txt'
$logContent = ''
$blockCount = 3
$eventDateTime = $(Get-Date -format yyyyMMdd`-HHmmss)
$lastHour = 24

#Check only last 24 hours
$DT = [DateTime]::Now.AddHours(-$lastHour) 

#Select Ip addresses that has audit failure 
$l = Get-EventLog -LogName 'Security' -InstanceId 4625 -After $DT | Select-Object @{n='IpAddress';e={$_.ReplacementStrings[-2]}}, TimeGenerated

#Get ip adresses, that have more than $blockCount wrong logins
$g = $l | group-object -property IpAddress | where {$_.Count -gt $blockCount}

#Get firewall object
$fw = New-Object -ComObject hnetcfg.fwpolicy2 

#Get firewall rule named 'BlockAttackers' (must be created manually)
$ar = $fw.rules | where {$_.name -eq 'BlockAttackers'} 

#Split the existing IPs into an array so we can search it for existing IPs
$arRemote = $ar.RemoteAddresses -split(',') 

#Only collect IPs that aren't already in the firewall rule
$w = @()
$w = $g | where {$_.Name.Length -gt 1 -and !($arRemote -contains $_.Name + '/255.255.255.255') }

#Add the new IPs to firewall rule
$c = 0
$w | %{ 
  if ($ar.RemoteAddresses -eq '*') {
		$ar.RemoteAddresses = $_.Name
	}else{
		$ar.RemoteAddresses += ',' + $_.Name
	}
  $logContent += $eventDateTime + '	' + $_.Name + " as blocked " + $blockCount + " time(s) failed within " + $lastHour + " hour(s) @ " + $w.Group[0].TimeGenerated.ToString("yyyyMMdd`-HHmmss") + "`r`n"
  $c += 1
}

#Report Summary
if ($c -gt 0) {
    $logContent += $eventDateTime + '	Summary : ' + $c + '/' + $t + ' Added'
}else{
    $logContent += $eventDateTime + '	' + $l[0].IpAddress + " as suspected @ " + $l[0].TimeGenerated.ToString("yyyyMMdd`-HHmmss")
}

#Write to eventlog when blocked
if ($c -gt 0) {
  Write-EventLog -LogName Application -Source "BlockRDP" -EntryType Information -EventId 0 -Category 0 -Message $logContent
}

#Write to logfile
$logContent >> $logPath
