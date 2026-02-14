<#
.SYNOPSIS
    AD Domain STIG - Module 1: Password Policy
.DESCRIPTION
    Configures domain password and account lockout policies
    Based on U_Active_Directory_Domain_V3R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Domain-Module01-Password-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Domain-Module01-Password-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "AD Domain Module 1: Password Policy" "INFO"
Write-Log "========================================" "INFO"

# Import Active Directory module
if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module not found. Installing..." "ERROR"
    Install-WindowsFeature -Name RSAT-AD-PowerShell
}
Import-Module ActiveDirectory

$domain = Get-ADDomain
Write-Log "Domain: $($domain.DNSRoot)" "INFO"
Write-Log "Domain DN: $($domain.DistinguishedName)" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $currentPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot
    $currentPolicy | Export-Clixml "$BackupDir\PasswordPolicy.xml"
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# WN19-DC-000010: Domain password policy
Write-Log "Configuring domain password policy..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would configure password policy:" "INFO"
    Write-Log "  - Min password length: 14 characters" "INFO"
    Write-Log "  - Password history: 24 passwords" "INFO"
    Write-Log "  - Max password age: 60 days" "INFO"
    Write-Log "  - Min password age: 1 day" "INFO"
    Write-Log "  - Lockout duration: 15 minutes" "INFO"
    Write-Log "  - Lockout threshold: 3 attempts" "INFO"
    Write-Log "  - Complexity enabled: Yes" "INFO"
}
else {
    try {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
            -MinPasswordLength 14 `
            -PasswordHistoryCount 24 `
            -MaxPasswordAge (New-TimeSpan -Days 60) `
            -MinPasswordAge (New-TimeSpan -Days 1) `
            -LockoutDuration (New-TimeSpan -Minutes 15) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
            -LockoutThreshold 3 `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false
        
        Write-Log "SUCCESS: Domain password policy configured" "SUCCESS"
    }
    catch {
        Write-Log "ERROR: Failed to configure password policy: $_" "ERROR"
    }
}

# WN19-DC-000200: Kerberos policy recommendations
Write-Log "Kerberos policy configuration..." "INFO"
Write-Log "NOTE: Kerberos policy must be configured via Default Domain Policy GPO:" "WARN"
Write-Log "  - Maximum lifetime for user ticket: 10 hours" "WARN"
Write-Log "  - Maximum lifetime for service ticket: 600 minutes" "WARN"
Write-Log "  - Maximum tolerance for computer clock sync: 5 minutes" "WARN"
Write-Log "  - Maximum lifetime for user ticket renewal: 7 days" "WARN"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 1 Completed: Password Policy" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "WARN"
Write-Log "1. Configure Kerberos policy in Default Domain Policy GPO" "WARN"
Write-Log "2. Consider Fine-Grained Password Policies for privileged accounts" "WARN"
Write-Log "3. Test user account creation with new password requirements" "WARN"
