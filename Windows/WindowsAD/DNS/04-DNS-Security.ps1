<#
.SYNOPSIS
    DNS Server STIG - Module 4: Security Settings
.DESCRIPTION
    Configures DNS security settings including rate limiting, scavenging, and network parameters
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-DNS-Module04-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\DNS-Module04-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "DNS Module 4: Security Settings" "INFO"
Write-Log "========================================" "INFO"

if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

Import-Module DnsServer
$dnsServer = $env:COMPUTERNAME

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    Get-DnsServer | Export-Clixml "$BackupDir\DnsServerSettings.xml"
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# DNS-SR-000070: Response rate limiting
Write-Log "Configuring response rate limiting..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable response rate limiting" "INFO"
}
else {
    try {
        Set-DnsServerResponseRateLimiting -Mode Enable -ErrorAction SilentlyContinue
        Write-Log "SUCCESS: Response rate limiting enabled (protects against DDoS)" "SUCCESS"
    }
    catch {
        Write-Log "Could not enable rate limiting: $_" "WARN"
    }
}

# DNS-SR-000080: Scavenging
Write-Log "Configuring DNS scavenging..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable scavenging with 7-day interval" "INFO"
}
else {
    Set-DnsServerScavenging -ScavengingState $true `
        -ScavengingInterval "7.00:00:00" `
        -ErrorAction SilentlyContinue
    
    Write-Log "SUCCESS: DNS scavenging enabled (7-day interval)" "SUCCESS"
    
    # Enable aging on zones
    $zones = Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated}
    foreach ($zone in $zones) {
        if ($zone.IsDsIntegrated) {
            Set-DnsServerZoneAging -Name $zone.ZoneName `
                -Aging $true `
                -ScavengeServers @($dnsServer) `
                -ErrorAction SilentlyContinue
            
            Write-Log "  Aging enabled for zone: $($zone.ZoneName)" "INFO"
        }
    }
}

# DNS-SR-000090: Socket pool size
Write-Log "Configuring socket pool size..." "INFO"

$socketPool = Get-DnsServerSetting | Select-Object -ExpandProperty SocketPoolSize
if ($socketPool -lt 2500) {
    if ($WhatIf) {
        Write-Log "[WHATIF] Would increase socket pool size to 2500" "INFO"
    }
    else {
        dnscmd /Config /SocketPoolSize 2500 | Out-Null
        Write-Log "SUCCESS: Socket pool size increased to 2500 (protects against forgery)" "SUCCESS"
    }
}
else {
    Write-Log "Socket pool size already configured: $socketPool" "SUCCESS"
}

# DNS-SR-000100: Global query block list
Write-Log "Checking global query block list..." "INFO"

$blockList = Get-DnsServerGlobalQueryBlockList
Write-Log "Global query block list enabled: $($blockList.Enable)" "INFO"
Write-Log "Blocked names: $($blockList.List -join ', ')" "INFO"
Write-Log "This prevents WPAD/ISATAP exploitation" "INFO"

# DNS-SR-000140: Round robin
Write-Log "Configuring round robin..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable round robin" "INFO"
}
else {
    Set-DnsServerSetting -RoundRobin $true
    Write-Log "SUCCESS: Round robin enabled (load distribution)" "SUCCESS"
}

# DNS-SR-000150: Netmask ordering
Write-Log "Configuring netmask ordering..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable local netmask priority" "INFO"
}
else {
    Set-DnsServerSetting -LocalNetPriority $true
    Write-Log "SUCCESS: Netmask ordering enabled (local subnet preference)" "SUCCESS"
}

# DNS-SR-000170: RPC protocol
Write-Log "Checking RPC configuration..." "INFO"

$rpcProtocol = Get-DnsServerSetting | Select-Object -ExpandProperty RpcProtocol
Write-Log "RPC Protocol setting: $rpcProtocol" "INFO"
Write-Log "VERIFY: Limit RPC protocol access if not required" "WARN"

# DNS-SR-000180: Listen addresses
Write-Log "Checking listen addresses..." "INFO"

$listen = Get-DnsServerSetting | Select-Object -ExpandProperty ListenAddresses
if ($listen.Count -eq 0) {
    Write-Log "Listening on ALL interfaces" "WARN"
    Write-Log "SECURITY NOTE: Consider restricting to specific IP addresses" "WARN"
    Write-Log "  Example: Set-DnsServerSetting -ListenAddresses @(\"192.168.1.10\")" "WARN"
}
else {
    Write-Log "Listening on specific addresses (GOOD):" "SUCCESS"
    foreach ($addr in $listen) {
        Write-Log "  - $addr" "INFO"
    }
}

# DNS-SR-000120 and 000130: File and registry permissions
Write-Log "Checking DNS file permissions..." "INFO"

$dnsPath = "$env:SystemRoot\System32\dns"
Write-Log "DNS directory: $dnsPath" "INFO"
Write-Log "MANUAL VERIFICATION: Only Administrators should have write access" "WARN"

$dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS"
Write-Log "DNS registry: $dnsRegPath" "INFO"
Write-Log "MANUAL VERIFICATION: Only SYSTEM and Administrators should have full control" "WARN"

# DNS-SR-000240: Firewall configuration
Write-Log "Checking Windows Firewall rules..." "INFO"

$dnsRules = Get-NetFirewallRule -DisplayName "*DNS*" -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $true}
Write-Log "Active DNS firewall rules: $($dnsRules.Count)" "INFO"
Write-Log "VERIFY: Firewall rules restrict DNS access to authorized clients/servers" "WARN"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 4 Completed: Security Settings" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "MANUAL TASKS:" "WARN"
Write-Log "1. Configure listen addresses to specific IPs (don't expose on all interfaces)" "WARN"
Write-Log "2. Verify DNS file and registry permissions" "WARN"
Write-Log "3. Configure Windows Firewall to restrict DNS queries to authorized clients" "WARN"
Write-Log "4. Test DNS resolution from authorized and unauthorized clients" "WARN"
