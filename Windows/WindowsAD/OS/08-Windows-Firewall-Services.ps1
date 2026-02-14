<#
.SYNOPSIS
    Windows Server 2019 STIG - Module 8: Windows Firewall and Services
.DESCRIPTION
    Configures Windows Firewall profiles and disables unnecessary services
    Based on U_MS_Windows_Server_2019_V3R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module08-Firewall-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module08-Firewall-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Module 8: Windows Firewall and Services" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" "$BackupDir\Firewall.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Windows Firewall - Domain Profile
Write-Log "Configuring Windows Firewall - Domain Profile..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000780: Enable Domain firewall"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "DefaultInboundAction" -Value 1 -Type DWord `
    -Description "WN22-CC-000790: Domain firewall - Block inbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "DefaultOutboundAction" -Value 0 -Type DWord `
    -Description "WN22-CC-000800: Domain firewall - Allow outbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\domainfw.log" -Type String `
    -Description "WN22-CC-000810: Domain firewall log path"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFileSize" -Value 16384 -Type DWord `
    -Description "WN22-CC-000820: Domain firewall log size (16 MB)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogDroppedPackets" -Value 1 -Type DWord `
    -Description "WN22-CC-000830: Domain firewall - Log dropped packets"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogSuccessfulConnections" -Value 1 -Type DWord `
    -Description "WN22-CC-000840: Domain firewall - Log successful connections"

# Windows Firewall - Private Profile
Write-Log "Configuring Windows Firewall - Private Profile..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000850: Enable Private firewall"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
    -Name "DefaultInboundAction" -Value 1 -Type DWord `
    -Description "WN22-CC-000860: Private firewall - Block inbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
    -Name "DefaultOutboundAction" -Value 0 -Type DWord `
    -Description "WN22-CC-000870: Private firewall - Allow outbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
    -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\privatefw.log" -Type String `
    -Description "WN22-CC-000880: Private firewall log path"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
    -Name "LogFileSize" -Value 16384 -Type DWord `
    -Description "WN22-CC-000890: Private firewall log size (16 MB)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
    -Name "LogDroppedPackets" -Value 1 -Type DWord `
    -Description "WN22-CC-000900: Private firewall - Log dropped packets"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
    -Name "LogSuccessfulConnections" -Value 1 -Type DWord `
    -Description "WN22-CC-000910: Private firewall - Log successful connections"

# Windows Firewall - Public Profile
Write-Log "Configuring Windows Firewall - Public Profile..." "INFO"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000920: Enable Public firewall"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -Name "DefaultInboundAction" -Value 1 -Type DWord `
    -Description "WN22-CC-000930: Public firewall - Block inbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -Name "DefaultOutboundAction" -Value 0 -Type DWord `
    -Description "WN22-CC-000940: Public firewall - Allow outbound by default"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
    -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type String `
    -Description "WN22-CC-000950: Public firewall log path"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
    -Name "LogFileSize" -Value 16384 -Type DWord `
    -Description "WN22-CC-000960: Public firewall log size (16 MB)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
    -Name "LogDroppedPackets" -Value 1 -Type DWord `
    -Description "WN22-CC-000970: Public firewall - Log dropped packets"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
    -Name "LogSuccessfulConnections" -Value 1 -Type DWord `
    -Description "WN22-CC-000980: Public firewall - Log successful connections"

# Create firewall log directories
if (!$WhatIf) {
    $logDir = "$env:SystemRoot\System32\logfiles\firewall"
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        Write-Log "Created firewall log directory: $logDir" "SUCCESS"
    }
}

# Disable unnecessary services
Write-Log "Configuring services..." "INFO"

$servicesToDisable = @(
    @{Name="FTPSVC"; Description="Microsoft FTP Service"},
    @{Name="RpcLocator"; Description="Remote Procedure Call (RPC) Locator"},
    @{Name="simptcp"; Description="Simple TCP/IP Services"}
    #@{Name="SNMP"; Description="SNMP Service"},
    #@{Name="SNMPTRAP"; Description="SNMP Trap"}
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        if ($WhatIf) {
            Write-Log "[WHATIF] Would disable $($svc.Description)" "INFO"
        }
        else {
            try {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled
                Write-Log "DISABLED: $($svc.Description)" "SUCCESS"
            }
            catch {
                Write-Log "WARN: Could not disable $($svc.Description): $_" "WARN"
            }
        }
    }
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 8 Completed: Windows Firewall and Services" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "IMPORTANT: Review firewall rules and ensure required application ports are allowed." "WARN"
Write-Log "For FTP server, you may need to allow ports 20, 21, and passive FTP port range." "WARN"
