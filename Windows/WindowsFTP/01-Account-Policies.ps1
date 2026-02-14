<#
.SYNOPSIS
    Windows Server 2022 STIG - Module 1: Account Policies
.DESCRIPTION
    Configures password and account lockout policies
    Based on U_MS_Windows_Server_2022_V2R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module01-Account-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module01-Account-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 1: Account Policies" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    secedit /export /cfg "$BackupDir\SecPol-Before.inf" /quiet
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Configure Account Policies
Write-Log "Configuring password and account lockout policies..." "INFO"

if (!$WhatIf) {
    try {
        $secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 3
ResetLockoutCount = 15
LockoutDuration = 15
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secpolContent | Out-File -FilePath $tempFile -Encoding unicode
        secedit /configure /db secedit.sdb /cfg $tempFile /quiet
        Remove-Item $tempFile
        Write-Log "Password and lockout policies configured successfully" "SUCCESS"
    }
    catch {
        Write-Log "ERROR applying security policies: $_" "ERROR"
        exit 1
    }
}
else {
    Write-Log "[WHATIF] Would configure password and lockout policies" "INFO"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 1 Completed: Account Policies" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "WARN"
Write-Log "Apply to existing users with:" "INFO"
Write-Log "  net accounts /maxpwage:60 /minpwage:1 /minpwlen:14" "INFO"
