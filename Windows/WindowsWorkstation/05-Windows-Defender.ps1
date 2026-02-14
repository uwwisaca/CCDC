<#
.SYNOPSIS
    Windows 11 24H2 STIG - Module 5: Windows Defender
.DESCRIPTION
    Configures Windows Defender and Microsoft Defender Application Guard
    Based on U_MS_Windows_11_V2R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module05-Defender-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module05-Defender-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 5: Windows Defender" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" "$BackupDir\Defender.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Windows Defender Antivirus
Write-Log "Configuring Windows Defender Antivirus..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Value 0 -Type DWord `
    -Description "WN22-CC-000440: Enable Windows Defender Antivirus"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord `
    -Description "WN22-CC-000450: Enable behavior monitoring"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord `
    -Description "WN22-CC-000460: Enable real-time protection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWord `
    -Description "WN22-CC-000470: Enable scan when real-time protection enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableIOAVProtection" -Value 0 -Type DWord `
    -Description "WN22-CC-000480: Enable scanning of downloaded files and attachments"

# Cloud-Delivered Protection
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -Name "SpynetReporting" -Value 1 -Type DWord `
    -Description "WN22-CC-000490: Cloud-delivered protection level (Basic)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -Name "SubmitSamplesConsent" -Value 1 -Type DWord `
    -Description "WN22-CC-000500: Submit samples consent (Send safe samples)"

# Exploit Protection
Write-Log "Configuring exploit protection..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" `
    -Name "DisallowExploitProtectionOverride" -Value 1 -Type DWord `
    -Description "WN22-CC-000510: Prevent users from modifying exploit protection"

# Attack Surface Reduction
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
    -Name "ExploitGuard_ASR_Rules" -Value 1 -Type DWord `
    -Description "WN22-CC-000520: Enable Attack Surface Reduction rules"

# Application Guard (if Enterprise edition)
Write-Log "Configuring Application Guard..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" `
    -Name "AllowAppHVSI_ProviderSet" -Value 3 -Type DWord `
    -Description "WN22-CC-000530: Application Guard for Office"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" `
    -Name "BlockNonEnterpriseContent" -Value 1 -Type DWord `
    -Description "WN22-CC-000540: Block non-enterprise content in Application Guard"

# SmartScreen
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
    -Name "EnableSmartScreen" -Value 1 -Type DWord `
    -Description "WN22-CC-000550: Enable Windows Defender SmartScreen"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
    -Name "ShellSmartScreenLevel" -Value "Block" -Type String `
    -Description "WN22-CC-000560: SmartScreen - Block"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 5 Completed: Windows Defender" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
