<#
.SYNOPSIS
    DNS Server STIG - Module 3: Forwarders and Recursion
.DESCRIPTION
    Configures DNS forwarders, recursion, and cache settings
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-DNS-Module03-Recursion-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\DNS-Module03-Recursion-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "DNS Module 3: Forwarders and Recursion" "INFO"
Write-Log "========================================" "INFO"

if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

Import-Module DnsServer

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $forwarders = Get-DnsServerForwarder
    $recursion = Get-DnsServerRecursion
    $cache = Get-DnsServerCache
    
    @{
        Forwarders = $forwarders
        Recursion = $recursion
        Cache = $cache
    } | Export-Clixml "$BackupDir\DnsRecursionSettings.xml"
    
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# DNS-SR-000040: Configure forwarders
Write-Log "Checking DNS forwarders..." "INFO"

$forwarders = Get-DnsServerForwarder
if ($forwarders.IPAddress.Count -eq 0) {
    Write-Log "No DNS forwarders configured" "WARN"
    Write-Log "  For recursive servers, configure forwarders to approved DNS servers" "WARN"
    Write-Log "  Example: Add-DnsServerForwarder -IPAddress 8.8.8.8" "WARN"
}
else {
    Write-Log "Configured forwarders:" "INFO"
    foreach ($fwd in $forwarders.IPAddress) {
        Write-Log "  - $fwd" "INFO"
    }
    Write-Log "VERIFY: Ensure these are approved organizational DNS servers" "WARN"
}

# DNS-SR-000050: Disable recursion on authoritative servers
Write-Log "Checking recursion settings..." "INFO"

$recursion = Get-DnsServerRecursion
Write-Log "Recursion enabled: $($recursion.Enable)" "INFO"

if ($recursion.Enable -eq $true) {
    Write-Log "Recursion is ENABLED" "WARN"
    Write-Log "  For authoritative-only DNS servers, recursion should be disabled" "WARN"
    Write-Log "  For recursive/caching servers, recursion is required" "INFO"
    Write-Log "  To disable: Set-DnsServerRecursion -Enable `$false" "WARN"
}
else {
    Write-Log "Recursion is disabled (authoritative server)" "SUCCESS"
}

# DNS-SR-000060: Configure cache settings
Write-Log "Configuring cache TTL settings..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would set MaxTtl to 1 day and MaxNegativeTtl to 15 minutes" "INFO"
}
else {
    Set-DnsServerCache -MaxTtl "1.00:00:00" -MaxNegativeTtl "00:15:00"
    Write-Log "SUCCESS: Cache TTL configured" "SUCCESS"
    Write-Log "  Max TTL: 1 day" "INFO"
    Write-Log "  Max Negative TTL: 15 minutes" "INFO"
}

# DNS-SR-000160: Secure cache against pollution
Write-Log "Configuring cache pollution protection..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable cache pollution protection" "INFO"
}
else {
    Set-DnsServerCache -PollutionProtection $true
    Write-Log "SUCCESS: Cache pollution protection enabled" "SUCCESS"
}

# DNS-SR-000190: Configure root hints
Write-Log "Checking root hints..." "INFO"

$rootHints = Get-DnsServerRootHint
Write-Log "Root hints configured: $($rootHints.Count)" "INFO"

if ($rootHints.Count -eq 0) {
    Write-Log "No root hints configured (authoritative-only server)" "INFO"
}
else {
    Write-Log "Root hints present for recursive resolution" "INFO"
    Write-Log "VERIFY: Ensure root hints are current and accurate" "WARN"
}

# DNS-SR-000200: Recursion scope
Write-Log "Recursion scope configuration..." "INFO"
Write-Log "MANUAL TASK: Configure recursion scopes to limit which clients can perform recursive queries" "WARN"
Write-Log "  Example for internal clients only:" "WARN"
Write-Log "    Add-DnsServerRecursionScope -Name \"InternalClients\"" "WARN"
Write-Log "    Set-DnsServerRecursionScope -Name \"InternalClients\" -EnableRecursion `$true" "WARN"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 3 Completed: Forwarders and Recursion" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "DECIDE:" "WARN"
Write-Log "- Is this an AUTHORITATIVE-ONLY server? Disable recursion." "WARN"
Write-Log "- Is this a RECURSIVE/CACHING server? Keep recursion enabled, configure forwarders." "WARN"
Write-Log "- Configure recursion scopes to limit which clients can recurse." "WARN"
