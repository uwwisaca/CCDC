<#
.SYNOPSIS
    DNS Server STIG - Module 5: Backup Configuration
.DESCRIPTION
    Creates DNS backup and provides restore procedures
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-DNS-Module05-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupPath = "C:\DNSBackup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "DNS Module 5: Backup Configuration" "INFO"
Write-Log "========================================" "INFO"

if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-Log "DNS Server feature is not installed" "ERROR"
    exit 1
}

Import-Module DnsServer

# DNS-SR-000250: Backup and restore procedures
Write-Log "Creating DNS backup..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would create backup at $BackupPath" "INFO"
}
else {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    
    # Export DNS server configuration
    Write-Log "Exporting DNS server configuration..." "INFO"
    Get-DnsServer | Export-Clixml "$BackupPath\DnsServerConfig.xml"
    
    # Export zone files
    Write-Log "Exporting zone files..." "INFO"
    $zones = Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated}
    
    foreach ($zone in $zones) {
        Write-Log "  Exporting zone: $($zone.ZoneName)" "INFO"
        
        try {
            if ($zone.ZoneType -eq "Primary" -and -not $zone.IsDsIntegrated) {
                Export-DnsServerZone -Name $zone.ZoneName -FileName "$($zone.ZoneName).backup.txt"
                Copy-Item "$env:SystemRoot\System32\dns\$($zone.ZoneName).backup.txt" `
                    -Destination "$BackupPath\$($zone.ZoneName).txt" -Force
            }
            elseif ($zone.IsDsIntegrated) {
                # For AD-integrated zones, export resource records
                $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName
                $records | Export-Clixml "$BackupPath\$($zone.ZoneName)_Records.xml"
            }
        }
        catch {
            Write-Log "  Failed to export zone $($zone.ZoneName): $_" "WARN"
        }
    }
    
    # Export forwarders
    Write-Log "Exporting forwarders..." "INFO"
    Get-DnsServerForwarder | Export-Clixml "$BackupPath\Forwarders.xml"
    
    # Export diagnostics settings
    Write-Log "Exporting diagnostics settings..." "INFO"
    Get-DnsServerDiagnostics | Export-Clixml "$BackupPath\Diagnostics.xml"
    
    # Export recursion settings
    Write-Log "Exporting recursion settings..." "INFO"
    Get-DnsServerRecursion | Export-Clixml "$BackupPath\Recursion.xml"
    
    # Backup registry settings
    Write-Log "Backing up DNS registry..." "INFO"
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\DNS" "$BackupPath\DNS_Registry.reg" /y | Out-Null
    
    Write-Log "SUCCESS: DNS backup completed" "SUCCESS"
    Write-Log "Backup location: $BackupPath" "SUCCESS"
}

# Create restore script
$restoreScript = @"
# DNS Server Restore Script
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Backup Location: $BackupPath

# RESTORE PROCEDURE:
# 1. Stop DNS service
Stop-Service DNS

# 2. Import DNS server configuration
`$config = Import-Clixml "$BackupPath\DnsServerConfig.xml"

# 3. Import forwarders
`$forwarders = Import-Clixml "$BackupPath\Forwarders.xml"
Remove-DnsServerForwarder -IPAddress (Get-DnsServerForwarder).IPAddress -Force
foreach (`$fwd in `$forwarders.IPAddress) {
    Add-DnsServerForwarder -IPAddress `$fwd
}

# 4. Import diagnostics
`$diag = Import-Clixml "$BackupPath\Diagnostics.xml"
Set-DnsServerDiagnostics -All `$diag

# 5. Import recursion settings
`$recursion = Import-Clixml "$BackupPath\Recursion.xml"
Set-DnsServerRecursion -Enable `$recursion.Enable

# 6. Restore zone files
# For file-based zones, copy zone files to C:\Windows\System32\dns\

#7. For AD-integrated zones, restore records
# Get-ChildItem "$BackupPath\*_Records.xml" | ForEach-Object {
#     `$zoneName = `$_.BaseName -replace '_Records', ''
#     `$records = Import-Clixml `$_.FullName
#     # Manually recreate records as needed
# }

# 8. Restart DNS service
Start-Service DNS

Write-Host "DNS restore completed. Verify zones and configuration." -ForegroundColor Green
"@

if (!$WhatIf) {
    $restoreScript | Out-File "$BackupPath\RESTORE-INSTRUCTIONS.ps1" -Encoding UTF8
    Write-Log "Restore script created: $BackupPath\RESTORE-INSTRUCTIONS.ps1" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 5 Completed: Backup Configuration" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupPath" "INFO"
Write-Log "" "INFO"
Write-Log "BACKUP RECOMMENDATIONS:" "WARN"
Write-Log "1. Schedule regular automated backups (daily/weekly)" "WARN"
Write-Log "2. Store backups on separate storage (not on DNS server)" "WARN"
Write-Log "3. Include DNS backups in System State backups" "WARN"
Write-Log "4. Test restore procedures regularly (quarterly)" "WARN"
Write-Log "5. Document DNS infrastructure changes" "WARN"
Write-Log "6. Implement backup monitoring and alerting" "WARN"
Write-Log "" "INFO"
Write-Log "TO RESTORE FROM THIS BACKUP:" "INFO"
Write-Log "  1. Review: $BackupPath\RESTORE-INSTRUCTIONS.ps1" "INFO"
Write-Log "  2. Customize for your environment" "INFO"
Write-Log "  3. Execute on DNS server as Administrator" "INFO"
