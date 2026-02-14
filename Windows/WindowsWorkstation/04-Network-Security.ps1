<#
.SYNOPSIS
    Windows 11 24H2 STIG - Module 4: Network Security
.DESCRIPTION
    Configures SMB, WinRM, DNS, and network security settings
    Based on U_MS_Windows_11_V2R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module04-Network-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module04-Network-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 4: Network Security" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" "$BackupDir\SMB.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM" "$BackupDir\WinRM.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# SMB Settings
Write-Log "Configuring SMB settings..." "INFO"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" -Value 0 -Type DWord `
    -Description "WN22-CC-000330: Disable SMB1"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000310: SMB Server - Require security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000320: SMB Client - Require security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "EnableSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000330: SMB Server - Enable security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnableSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000340: SMB Client - Enable security signature"

# Disable NetBIOS over TCP/IP
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
    -Name "NodeType" -Value 2 -Type DWord `
    -Description "WN22-CC-000340: Configure NetBIOS node type"

# Windows Remote Management
Write-Log "Configuring WinRM settings..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN22-CC-000350: WinRM Client - Disallow Basic auth"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN22-CC-000360: WinRM Client - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN22-CC-000370: WinRM Service - Disallow Basic auth"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN22-CC-000380: WinRM Service - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "DisableRunAs" -Value 1 -Type DWord `
    -Description "WN22-CC-000390: WinRM Service - Disable RunAs"

# Hardened UNC Paths
Write-Log "Configuring hardened UNC paths..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN22-CC-000400: Hardened UNC Path - NETLOGON"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN22-CC-000410: Hardened UNC Path - SYSVOL"

# DNS Client Settings
Write-Log "Configuring DNS client settings..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord `
    -Description "WN22-CC-000420: Disable Multicast Name Resolution"

# Disable LLMNR
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableLLMNR" -Value 0 -Type DWord `
    -Description "WN22-CC-000430: Disable LLMNR"

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 4 Completed: Network Security" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
