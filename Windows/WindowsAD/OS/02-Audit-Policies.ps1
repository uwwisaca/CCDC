<#
.SYNOPSIS
    Windows Server 2019 STIG - Module 2: Audit Policies
.DESCRIPTION
    Configures advanced audit policies
    Based on U_MS_Windows_Server_2019_V3R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module02-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module02-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 2: Audit Policies" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    auditpol /backup /file:"$BackupDir\AuditPol-Before.csv"
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Advanced Audit Policies
$auditPolicies = @(
    @{Subcategory = "Credential Validation"; Setting = "Success,Failure"}
    @{Subcategory = "Security Group Management"; Setting = "Success"}
    @{Subcategory = "User Account Management"; Setting = "Success,Failure"}
    @{Subcategory = "Computer Account Management"; Setting = "Success"}
    @{Subcategory = "Other Account Management Events"; Setting = "Success,Failure"}
    @{Subcategory = "Process Creation"; Setting = "Success"}
    @{Subcategory = "Process Termination"; Setting = "Success"}
    @{Subcategory = "Account Lockout"; Setting = "Failure"}
    @{Subcategory = "Logoff"; Setting = "Success"}
    @{Subcategory = "Logon"; Setting = "Success,Failure"}
    @{Subcategory = "Special Logon"; Setting = "Success"}
    @{Subcategory = "Audit Policy Change"; Setting = "Success"}
    @{Subcategory = "Authentication Policy Change"; Setting = "Success"}
    @{Subcategory = "Authorization Policy Change"; Setting = "Success"}
    @{Subcategory = "Sensitive Privilege Use"; Setting = "Success,Failure"}
    @{Subcategory = "IPsec Driver"; Setting = "Success,Failure"}
    @{Subcategory = "Security State Change"; Setting = "Success"}
    @{Subcategory = "Security System Extension"; Setting = "Success"}
    @{Subcategory = "System Integrity"; Setting = "Success,Failure"}
)

foreach ($policy in $auditPolicies) {
    if (!$WhatIf) {
        try {
            auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>$null
            Write-Log "Set audit policy: $($policy.Subcategory)" "SUCCESS"
        }
        catch {
            Write-Log "ERROR setting audit policy $($policy.Subcategory): $_" "ERROR"
        }
    }
    else {
        Write-Log "[WHATIF] Would set audit policy: $($policy.Subcategory)" "INFO"
    }
}

# Force audit policy subcategory settings
if (!$WhatIf) {
    if (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Lsa")) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force
    Write-Log "Forced audit policy subcategory settings" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 2 Completed: Audit Policies" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "Verify with: auditpol /get /category:*" "INFO"
