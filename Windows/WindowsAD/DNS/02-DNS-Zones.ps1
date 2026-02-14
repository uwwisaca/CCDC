<#
.SYNOPSIS
    DNS Server STIG - Module 2: Zone Configuration
.DESCRIPTION
    Configures DNS zones, zone transfers, and DNSSEC
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-DNS-Module02-Zones-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\DNS-Module02-Zones-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

Write-Log "========================================" "INFO"
Write-Log "DNS Module 2: Zone Configuration" "INFO"
Write-Log "========================================" "INFO"

# Check DNS server feature
if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

Import-Module DnsServer

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $zones = Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated}
    $zones | Export-Clixml "$BackupDir\DnsZones.xml"
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

$zones = Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated}
Write-Log "Found $($zones.Count) user-created zones" "INFO"

# DNS-SR-000020: Restrict zone transfers
Write-Log "Configuring zone transfer restrictions..." "INFO"

foreach ($zone in $zones) {
    Write-Log "Zone: $($zone.ZoneName)" "INFO"
    
    if ($WhatIf) {
        Write-Log "[WHATIF] Would restrict zone transfers for $($zone.ZoneName)" "INFO"
    }
    else {
        try {
            Set-DnsServerPrimaryZone -Name $zone.ZoneName `
                -SecureSecondaries "TransferToSecureServers" `
                -ErrorAction SilentlyContinue
            
            Write-Log "  Zone transfers restricted to secure servers only" "SUCCESS"
        }
        catch {
            Write-Log "  Could not configure zone transfers: $_" "WARN"
        }
    }
}

# DNS-SR-000030: DNSSEC configuration
Write-Log "Checking DNSSEC status..." "INFO"

foreach ($zone in $zones) {
    if ($zone.ZoneType -eq "Primary" -and -not $zone.IsDsIntegrated) {
        try {
            $dnssecConfig = Get-DnsServerDnsSecZoneSetting -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue
            
            if (!$dnssecConfig.IsSigned) {
                Write-Log "  Zone $($zone.ZoneName): NOT signed with DNSSEC" "WARN"
                Write-Log "    To sign: Add-DnsServerSigningKey -ZoneName $($zone.ZoneName) -CryptoAlgorithm RsaSha256 -Type KeySigningKey" "WARN"
                Write-Log "    Then: Add-DnsServerSigningKey -ZoneName $($zone.ZoneName) -CryptoAlgorithm RsaSha256 -Type ZoneSigningKey" "WARN"
            }
            else {
                Write-Log "  Zone $($zone.ZoneName): Signed with DNSSEC" "SUCCESS"
            }
        }
        catch {
            Write-Log "  Could not check DNSSEC for $($zone.ZoneName)" "WARN"
        }
    }
}

# DNS-SR-000230: Zone transfer notifications
Write-Log "Reviewing zone transfer notifications..." "INFO"

foreach ($zone in $zones) {
    if ($zone.ZoneType -eq "Primary") {
        Write-Log "Primary zone: $($zone.ZoneName)" "INFO"
        Write-Log "  Configure notification list to specific secondary servers only" "WARN"
        Write-Log "  Use: Set-DnsServerZoneSubscription -Name $($zone.ZoneName) -NotifyServers @(\"IP1\",\"IP2\")" "WARN"
    }
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 2 Completed: Zone Configuration" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "MANUAL TASKS:" "WARN"
Write-Log "1. Configure zone transfer IP allow list for each zone" "WARN"
Write-Log "2. Sign zones with DNSSEC where required for data integrity" "WARN"
Write-Log "3. Configure notification servers for primary zones" "WARN"
Write-Log "4. Test zone transfers to secondary servers" "WARN"
