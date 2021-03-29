#Checks for IP addresses that used incorrect password more than 10 times
#within 24 hours and blocks them using a firewall rule 'BlockAttackers'

$logPath = '.\blocked.txt'

#Check only last 24 hours
$DT = [DateTime]::Now.AddHours(-24) 

#Select Ip addresses that has audit failure 
$l = Get-EventLog -LogName 'Security' -InstanceId 4625 -After $DT | Select-Object @{n='IpAddress';e={$_.ReplacementStrings[-2]} }

#Get ip adresses, that have more than 10 wrong logins
$g = $l | group-object -property IpAddress  | where {$_.Count -gt 10} | Select -property Name 

#Get firewall object
$fw = New-Object -ComObject hnetcfg.fwpolicy2 

#Get firewall rule named 'BlockAttackers' (must be created manually)
$ar = $fw.rules | where {$_.name -eq 'BlockAttackers'} 

#Split the existing IPs into an array so we can search it for existing IPs
$arRemote = $ar.RemoteAddresses -split(',') 

#Only collect IPs that aren't already in the firewall rule
$w = $g | where {$_.Name.Length -gt 1 -and !($arRemote -contains $_.Name + '/255.255.255.255') }

#Add the new IPs to firewall rule
$c = 0
$w| %{ 
  if ($ar.RemoteAddresses -eq '*') {
		$ar.RemoteAddresses = $_.Name
	}else{
		$ar.RemoteAddresses += ',' + $_.Name
	}
  $c += 1
}

#Write to logfile
$t = $arRemote.Length
if ($c -gt 0) {
  $w| %{(Get-Date).ToString() + '	' + $_.Name >> $logPath}
  $t += $c
}

(Get-Date).ToString() + '	Summary : ' + $c + '/' + $t + ' Added ' >> $logPath
