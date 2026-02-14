<#
.SYNOPSIS
    DNS Server STIG - Module 1: Logging Configuration
.DESCRIPTION
    Configures DNS server logging and event log settings
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-DNS-Module01-Logging-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\DNS-Module01-Logging-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "DNS Module 1: Logging Configuration" "INFO"
Write-Log "========================================" "INFO"

# Check if DNS server feature is installed
if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

# Import DNS module
Import-Module DnsServer

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    
    # Export current DNS diagnostics settings
    $currentDiag = Get-DnsServerDiagnostics
    $currentDiag | Export-Clixml "$BackupDir\DnsDiagnostics.xml"
    
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# DNS-SR-000010: Configure DNS logging
Write-Log "Configuring DNS server diagnostics..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable comprehensive DNS logging" "INFO"
}
else {
    Set-DnsServerDiagnostics -All $true `
        -LogFilePath "C:\Windows\System32\dns\dns.log" `
        -MaxMBFileSize 500000000
    
    Write-Log "SUCCESS: DNS logging enabled" "SUCCESS"
    Write-Log "  Log file: C:\Windows\System32\dns\dns.log" "INFO"
    Write-Log "  Max size: 500 MB" "INFO"
}

# DNS-SR-000110: Event log size
Write-Log "Configuring DNS event log size..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would set DNS event log to 16 MB" "INFO"
}
else {
    wevtutil sl "DNS Server" /ms:16777216
    Write-Log "SUCCESS: DNS event log configured to 16 MB" "SUCCESS"
}

# DNS-SR-000210: Audit policy
Write-Log "Configuring DNS audit diagnostics..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable DNS audit logging" "INFO"
}
else {
    Set-DnsServerDiagnostics -EnableDnsSec ValidationFailures $true `
        -EnableLoggingForZoneDataWrite $true `
        -EnableLoggingForZoneLoad $true `
        -EnableLoggingForPluginDllEvent $true
    
    Write-Log "SUCCESS: DNS audit diagnostics enabled" "SUCCESS"
}

# DNS-SR-000220: Analytics and debug logs
Write-Log "Enabling analytics and audit event logs..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable DNS analytical and audit logs" "INFO"
}
else {
    wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true 2>$null
    wevtutil sl "Microsoft-Windows-DNSServer/Audit" /e:true 2>$null
    
    Write-Log "SUCCESS: Analytical and audit logs enabled" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 1 Completed: DNS Logging" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "WARN"
Write-Log "- Monitor DNS event logs for anomalies" "WARN"
Write-Log "- Review C:\Windows\System32\dns\dns.log regularly" "WARN"
Write-Log "- Implement SIEM integration for DNS logs" "WARN"
