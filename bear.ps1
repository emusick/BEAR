# Bastion Environment for Advanced Response / Audit and Reporting (BEAR)
#
# TODO:
#   - ensure all Get-Service output is accommodated in XML (reverse Audit-Service foreach logic)
#	- address non-admin issue
#	- add wrapper for registry hardening to ensure path exists
#		https://blogs.technet.microsoft.com/heyscriptingguy/2015/04/02/update-or-add-registry-key-value-with-powershell/

$helpMenuChoice = $args[0]

function Show-Help($helpMenuChoice) {	
	while ($helpMenuChoice -lt 1 -or $helpMenuChoice -gt 3) {
		Write-Host ""
		Write-Host "1. Audit host"
		Write-Host "2. Harden host"
		Write-Host "3. Exit"
		Write-Host ""
	
		$helpMenuChoice = Read-Host "Select an option"
	}
	
	Switch($helpMenuChoice) {
			1 {Audit-Host}
			2 {Harden-Host}
			3 {exit}
			default {Show-Help}
	}
	
	Write-Host ""
}

function Audit-Host {
	Write-Host ""
	Write-Host "Begin host audit."
	Write-Host ""
	
	Audit-Registry
	Audit-Services
}

function Harden-Host {
	Write-Host ""
	Write-Host "Begin host hardening."
	Write-Host ""
	
	Harden-Registry
	Harden-Services
}

function Audit-Registry {
	[xml]$configuration = Get-Content -Path .\registry.xml

	foreach ($ci in $configuration.configuration.registry) {
		# http://stackoverflow.com/questions/15511809/how-do-i-get-the-value-of-a-registry-key-and-only-the-value-using-powershell
		$observedState = Get-ItemPropertyValue -Path $ci."path" -Name $ci."key"
		
		If ($observedState -match $ci."expected") {
			Write-host ("Passed: {0}\{1}" -f $ci."path", $ci."key")
		}
		Else { Write-host -ForegroundColor "red" "Failed:" $ci."path" "\" $ci."key"
		}
	}
	
	Write-Host ""
	Write-Host "Completed registry hardening."
	Write-Host ""
}

function Audit-Services {
	[xml]$configuration = Get-Content -Path .\service.xml

	foreach ($ci in $configuration.configuration.service) {
		$observedState = Get-Service | Select-Object -Property Name,StartType | where-object {$_.Name -eq $ci."name"}
		$obs = $observedState.StartType
		
		If ($obs -match $ci."expected") {
			Write-host "Passed:" $ci."name"
		}
		Else { Write-host -ForegroundColor "red" "Failed:" $ci."name"
		}
	}
	
	Write-Host ""
	Write-Host "Completed service audit."
}

function Harden-Registry {
	[xml]$configuration = Get-Content -Path .\registry.xml

	foreach ($ci in $configuration.configuration.registry) {
		Set-ItemProperty -Path $ci."path" -Name $ci."key" -Type $ci."type" -Value $ci."expected" # 2>&1 | out-null
	}
	
	Write-Host ""
	Write-Host "Completed egistry audit."
	Write-Host ""
}

function Harden-Services {
	[xml]$configuration = Get-Content -Path .\service.xml

	foreach ($ci in $configuration.configuration.service) {
		Stop-Service $ci."name" 2>&1 | out-null
		Set-Service $ci."name" -StartupType $ci."expected" 2>&1 | out-null
	}
	
	Write-Host "Completed service hardening."
}

Show-Help($helpMenuChoice)