<#
.SYNOPSIS
    Windows Server 2019 STIG - Module 6: RDS and PowerShell
.DESCRIPTION
    Configures Remote Desktop Services, PowerShell logging, and script execution
    Based on U_MS_Windows_Server_2019_V3R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module06-RDS-PowerShell-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module06-RDS-PowerShell-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 6: RDS and PowerShell" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "$BackupDir\TerminalServices.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "$BackupDir\PowerShell.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Remote Desktop Services
Write-Log "Configuring Remote Desktop Services..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic" -Value 1 -Type DWord `
    -Description "WN22-CC-000570: RDS - Encrypt RPC traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel" -Value 3 -Type DWord `
    -Description "WN22-CC-000580: RDS - Encryption level (High)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "SecurityLayer" -Value 2 -Type DWord `
    -Description "WN22-CC-000590: RDS - Security layer (SSL/TLS)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "UserAuthentication" -Value 1 -Type DWord `
    -Description "WN22-CC-000600: RDS - Require Network Level Authentication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword" -Value 1 -Type DWord `
    -Description "WN22-CC-000610: RDS - Always prompt for password"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fDisableCdm" -Value 1 -Type DWord `
    -Description "WN22-CC-000620: RDS - Disable drive redirection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "DeleteTempDirsOnExit" -Value 1 -Type DWord `
    -Description "WN22-CC-000630: RDS - Delete temp folders on exit"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "PerSessionTempDir" -Value 1 -Type DWord `
    -Description "WN22-CC-000640: RDS - Use per-session temp folders"

# PowerShell Settings
Write-Log "Configuring PowerShell..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord `
    -Description "WN22-CC-000650: Enable PowerShell script block logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockInvocationLogging" -Value 0 -Type DWord `
    -Description "WN22-CC-000660: PowerShell script block invocation logging (disabled for performance)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord `
    -Description "WN22-CC-000670: Enable PowerShell module logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -Value 1 -Type DWord `
    -Description "WN22-CC-000680: Enable PowerShell transcription"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell_Transcript" -Type String `
    -Description "WN22-CC-000690: PowerShell transcription output directory"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableInvocationHeader" -Value 1 -Type DWord `
    -Description "WN22-CC-000700: PowerShell transcription invocation header"

# Create PowerShell transcript directory
if (!$WhatIf) {
    New-Item -ItemType Directory -Path "C:\Windows\Logs\PowerShell_Transcript" -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Created PowerShell transcript directory" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 6 Completed: RDS and PowerShell" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
