<#
.SYNOPSIS
    Windows 11 24H2 STIG - Module 3: Security Options
.DESCRIPTION
    Configures security options including UAC, legal notices, LSA protection
    Based on U_MS_Windows_11_V2R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module03-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module03-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        if ($WhatIf) {
            Write-Log "[WHATIF] Would set $Path\$Name = $Value ($Type)" "INFO"
            return
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "SUCCESS: $Description" "SUCCESS"
    }
    catch {
        Write-Log "ERROR setting $Path\$Name : $_" "ERROR"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Module 3: Security Options" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" "$BackupDir\Policies.reg" /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupDir\LSA.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Legal Notice
Write-Log "Configuring legal notice..." "INFO"

$legalNoticeText = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
"@

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText" -Value $legalNoticeText -Type String `
    -Description "WN22-SO-000130: Legal notice text"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Value "DoD Notice and Consent Banner" -Type String `
    -Description "WN22-SO-000140: Legal notice caption"

# Machine Inactivity Limit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Value 900 -Type DWord `
    -Description "WN22-SO-000120: Machine inactivity limit (15 minutes)"

# UAC Settings
Write-Log "Configuring UAC settings..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1 -Type DWord `
    -Description "WN22-SO-000260: Enable UAC"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord `
    -Description "WN22-SO-000270: UAC - Prompt for consent"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableInstallerDetection" -Value 1 -Type DWord `
    -Description "WN22-SO-000280: UAC - Detect application installations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableSecureUIAPaths" -Value 1 -Type DWord `
    -Description "WN22-SO-000290: UAC - Only elevate UIAccess apps in secure locations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableVirtualization" -Value 1 -Type DWord `
    -Description "WN22-SO-000300: UAC - Virtualize file and registry write failures"

# LSA Protection
Write-Log "Configuring LSA protection..." "INFO"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord `
    -Description "WN22-CC-000160: LSA Protection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" `
    -Name "AuditLevel" -Value 8 -Type DWord `
    -Description "WN22-CC-000170: LSASS Audit Mode"

# Disable LM Hash
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "NoLMHash" -Value 1 -Type DWord `
    -Description "WN22-SO-000150: Disable LM Hash"

# LAN Manager Authentication Level
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord `
    -Description "WN22-SO-000190: LAN Manager authentication level (NTLMv2 only)"

# Disable anonymous SID/Name translation
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "TurnOffAnonymousBlock" -Value 1 -Type DWord `
    -Description "WN22-SO-000080: Disable anonymous SID/Name translation"

# Do not allow anonymous enumeration of SAM accounts
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1 -Type DWord `
    -Description "WN22-SO-000100: Restrict anonymous SAM enumeration"

# Do not allow anonymous enumeration of shares
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1 -Type DWord `
    -Description "WN22-SO-000110: Restrict anonymous share enumeration"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 3 Completed: Security Options" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
