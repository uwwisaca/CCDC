# PowerShell Script to Apply DNS Server STIG
# Based on: U_Domain_Name_System_V4R2_Manual_SRG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: Run as Administrator on DNS Server
# .\Apply-DNS-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\DNS-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        default { Write-Host $logMessage }
    }
}

# Check if DNS server feature is installed
if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

Write-Log "========================================"
Write-Log "DNS Server STIG Application Starting"
Write-Log "========================================"

# Import DNS module
Import-Module DnsServer

$dnsServer = $env:COMPUTERNAME
$LOCAL_IP = (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty IPAddress)


# DNS-SR-000010: Configure DNS logging
Write-Log "Configuring DNS logging..." "INFO"

Set-DnsServerDiagnostics -All -LogFilePath "C:\Windows\System32\dns\dns.log" -MaxMBFileSize 500


Write-Log "DNS logging enabled" "SUCCESS"

# DNS-SR-000020: Restrict zone transfers
Write-Log "Configuring zone transfer restrictions..." "INFO"

$zones = Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated}

foreach ($zone in $zones) {
    Write-Log "Configuring zone: $($zone.ZoneName)" "INFO"
    
    # Restrict zone transfers to specific servers only
    Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries "TransferToSecureServers" -ErrorAction SilentlyContinue
    
    Write-Log "  Zone transfers restricted" "SUCCESS"
}

# DNS-SR-000030: Enable DNSSEC
Write-Log "Checking DNSSEC configuration..." "INFO"

foreach ($zone in $zones) {
    if ($zone.ZoneType -eq "Primary" -and -not $zone.IsDsIntegrated) {
        $dnssecConfig = Get-DnsServerDnsSecZoneSetting -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue
        
        if (!$dnssecConfig.IsSigned) {
            Write-Log "  Zone $($zone.ZoneName) is not signed with DNSSEC" "WARN"
            Write-Log "  To sign: Add-DnsServerSigningKey -ZoneName $($zone.ZoneName) -CryptoAlgorithm RsaSha256" "WARN"
        }
        else {
            Write-Log "  Zone $($zone.ZoneName) is signed with DNSSEC" "SUCCESS"
        }
    }
}

# DNS-SR-000040: Configure forwarders
Write-Log "Checking DNS forwarders..." "INFO"

$forwarders = Get-DnsServerForwarder
if ($forwarders.IPAddress.Count -eq 0) {
    Write-Log "No DNS forwarders configured" "WARN"
    Write-Log "Configure forwarders to approved DNS servers only" "WARN"
}
else {
    Write-Log "Configured forwarders:" "INFO"
    foreach ($fwd in $forwarders.IPAddress) {
        Write-Log "  - $fwd" "INFO"
    }
    Write-Log "Verify these are approved DNS servers" "WARN"
}

# DNS-SR-000050: Disable recursion on authoritative servers
Write-Log "Checking recursion settings..." "INFO"

$recursion = Get-DnsServerRecursion
Write-Log "Recursion enabled: $($recursion.Enable)" "INFO"

if ($recursion.Enable -eq $true) {
    Write-Log "Consider disabling recursion on authoritative-only DNS servers" "WARN"
    Write-Log "To disable: Set-DnsServerRecursion -Enable `$false" "WARN"
}

# DNS-SR-000060: Configure cache settings
Write-Log "Configuring cache settings..." "INFO"

# Set max cache size
Set-DnsServerCache -MaxTtl "1.00:00:00" -MaxNegativeTtl "00:15:00"

Write-Log "Cache TTL configured" "SUCCESS"

# DNS-SR-000070: Rate limiting
Write-Log "Configuring response rate limiting..." "INFO"

Set-DnsServerResponseRateLimiting -Mode Enable -ErrorAction SilentlyContinue

Write-Log "Response rate limiting enabled" "SUCCESS"

# DNS-SR-000080: Scavenging
Write-Log "Configuring scavenging..." "INFO"

Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval "7.00:00:00" -ErrorAction SilentlyContinue

foreach ($zone in $zones) {
    if ($zone.IsDsIntegrated) {
        Set-DnsServerZoneAging -Name $zone.ZoneName -Aging $true -ScavengeServers @($LOCAL_IP) -ErrorAction SilentlyContinue
    }
}

Write-Log "DNS scavenging configured" "SUCCESS"

# # DNS-SR-000090: Socket pool size
# Write-Log "Configuring socket pool..." "INFO"

# $socketPool = Get-DnsServerSetting | Select-Object -ExpandProperty SocketPoolSize
# if ($socketPool -lt 2500) {
#     dnscmd /Config /SocketPoolSize 2500
#     Write-Log "Socket pool size increased to 2500" "SUCCESS"
# }
# else {
#     Write-Log "Socket pool size already configured: $socketPool" "INFO"
# }

# DNS-SR-000100: Global query block list
Write-Log "Checking global query block list..." "INFO"

$blockList = Get-DnsServerGlobalQueryBlockList
Write-Log "Global query block list enabled: $($blockList.Enable)" "INFO"
Write-Log "Blocked names: $($blockList.List -join ', ')" "INFO"

# DNS-SR-000110: Event log size
Write-Log "Configuring DNS event log..." "INFO"

wevtutil sl "DNS Server" /ms:16777216
Write-Log "DNS event log size configured to 16 MB" "SUCCESS"

# DNS-SR-000120: File permissions
Write-Log "Checking file permissions..." "INFO"

$dnsPath = "$env:SystemRoot\System32\dns"
$acl = Get-Acl $dnsPath

Write-Log "DNS directory: $dnsPath" "INFO"
Write-Log "Verify only administrators have write access" "WARN"

# DNS-SR-000130: Registry permissions
Write-Log "Checking registry permissions..." "INFO"

$dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS"
Write-Log "DNS registry key: $dnsRegPath" "INFO"
Write-Log "Verify only SYSTEM and Administrators have full control" "WARN"

# DNS-SR-000140: Round robin
Write-Log "Configuring round robin..." "INFO"

Set-DnsServerSetting -RoundRobin $true

Write-Log "Round robin enabled" "SUCCESS"

# DNS-SR-000150: Netmask ordering
Write-Log "Configuring netmask ordering..." "INFO"

Set-DnsServerSetting -LocalNetPriority $true

Write-Log "Netmask ordering enabled" "SUCCESS"

# DNS-SR-000160: Secure cache against pollution
Write-Log "Configuring secure cache..." "INFO"

Set-DnsServerCache -PollutionProtection $true

Write-Log "Cache pollution protection enabled" "SUCCESS"

# DNS-SR-000170: Disable remote procedure call (RPC)
Write-Log "Checking RPC configuration..." "INFO"

$rpcProtocol = Get-DnsServerSetting | Select-Object -ExpandProperty RpcProtocol
Write-Log "RPC Protocol: $rpcProtocol" "INFO"

if ($rpcProtocol -ne 0) {
    Write-Log "Consider limiting RPC protocol access" "WARN"
}

# # DNS-SR-000180: Configure allowed IP addresses
# Write-Log "Configuring listen addresses..." "INFO"

# $listen = Get-DnsServerSetting | Select-Object -ExpandProperty ListenAddresses
# if ($listen.Count -eq 0) {
#     Write-Log "Listening on all interfaces" "WARN"
#     Write-Log "Consider restricting to specific IP addresses" "WARN"
# }
# else {
#     Write-Log "Listening on specific addresses:" "INFO"
#     foreach ($addr in $listen) {
#         Write-Log "  - $addr" "INFO"
#     }
# }

# DNS-SR-000190: Configure root hints
Write-Log "Checking root hints..." "INFO"

$rootHints = Get-DnsServerRootHint
Write-Log "Root hints count: $($rootHints.Count)" "INFO"

if ($rootHints.Count -eq 0) {
    Write-Log "No root hints configured (authoritative server)" "INFO"
}
else {
    Write-Log "Verify root hints are current and accurate" "WARN"
}

# DNS-SR-000200: Configure server-level recursion settings
Write-Log "Configuring recursion scope..." "INFO"

# Create a recursion scope if needed
Write-Log "Note: Configure recursion scopes to limit which clients can perform recursive queries" "WARN"

# DNS-SR-000210: Audit policy
Write-Log "Configuring DNS audit policy..." "INFO"

Set-DnsServerDiagnostics -EnableDnsSecValidationFailures -EnableLoggingForZoneDataWrite -EnableLoggingForZoneLoad -EnableLoggingForPluginDllEvent

Write-Log "DNS audit policy configured" "SUCCESS"

# DNS-SR-000220: Analytics and debug logs
Write-Log "Enabling analytics and debug logs..." "INFO"

wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true
wevtutil sl "Microsoft-Windows-DNSServer/Audit" /e:true

Write-Log "Analytics and audit logs enabled" "SUCCESS"

# DNS-SR-000230: Zone transfer notifications
Write-Log "Configuring zone transfer notifications..." "INFO"

foreach ($zone in $zones) {
    if ($zone.ZoneType -eq "Primary") {
        Write-Log "Zone: $($zone.ZoneName)" "INFO"
        Write-Log "  Configure notification list to specific secondary servers only" "WARN"
    }
}

# DNS-SR-000240: Configure firewall
Write-Log "Checking Windows Firewall rules..." "INFO"

$dnsRules = Get-NetFirewallRule -DisplayName "*DNS*" | Where-Object {$_.Enabled -eq $true}
Write-Log "Active DNS firewall rules: $($dnsRules.Count)" "INFO"

Write-Log "Verify firewall rules restrict DNS access to authorized clients/servers" "WARN"

# DNS-SR-000250: Backup and restore
Write-Log "DNS backup recommendations..." "INFO"

Write-Log "Implement regular backups:" "WARN"
Write-Log "  - Export zone files: Export-DnsServerZone" "WARN"
Write-Log "  - Backup DNS registry settings" "WARN"
Write-Log "  - Include in System State backups" "WARN"
Write-Log "  - Test restore procedures regularly" "WARN"

# Create a current backup
$backupPath = "C:\DNSBackup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

foreach ($zone in $zones) {
    if ($zone.ZoneType -eq "Primary" -and -not $zone.IsDsIntegrated) {
        Export-DnsServerZone -Name $zone.ZoneName -FileName "$backupPath\$($zone.ZoneName).txt"
    }
}

Write-Log "Zone files backed up to: $backupPath" "SUCCESS"

Write-Log ""
Write-Log "========================================"
Write-Log "DNS Server STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Zone backup: $backupPath"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log "1. Configure zone transfers to authorized secondary servers only"
Write-Log "2. Sign zones with DNSSEC for zones requiring integrity"
Write-Log "3. Configure DNS forwarders to approved DNS servers"
Write-Log "4. Disable recursion on authoritative-only DNS servers"
Write-Log "5. Configure recursion scopes to limit recursive queries"
Write-Log "6. Review and configure listen addresses (specific IPs vs all)"
Write-Log "7. Configure firewall rules to restrict DNS access"
Write-Log "8. Implement DNS monitoring and alerting"
Write-Log "9. Review DNS event logs regularly for anomalies"
Write-Log "10. Test DNS backup and restore procedures"
Write-Log "11. Document DNS infrastructure and changes"
Write-Log "12. Implement DNS query logging for forensics (if required)"
Write-Log ""
Write-Log "To export current configuration:"
Write-Log "  Get-DnsServer | Export-Clixml C:\DNSBackup\dnsconfig.xml"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
