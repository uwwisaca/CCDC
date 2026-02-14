<#
.SYNOPSIS
    Windows Server 2019 STIG - Module 7: Event Logs
.DESCRIPTION
    Configures event log settings, sizes, and retention policies
    Based on U_MS_Windows_Server_2019_V3R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module07-EventLogs-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module07-EventLogs-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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

function Set-EventLogSize {
    param(
        [string]$LogName,
        [int]$MaxSize,
        [string]$Description
    )
    
    try {
        if ($WhatIf) {
            Write-Log "[WHATIF] Would set $LogName log size to $MaxSize bytes" "INFO"
            return
        }
        
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $log.MaximumSizeInBytes = $MaxSize
        $log.SaveChanges()
        Write-Log "SUCCESS: $Description - Set to $($MaxSize/1MB) MB" "SUCCESS"
    }
    catch {
        Write-Log "ERROR setting $LogName size: $_" "ERROR"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Module 7: Event Log Configuration" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog" "$BackupDir\EventLog.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Application Log
Write-Log "Configuring Application event log..." "INFO"

Set-EventLogSize -LogName "Application" -MaxSize 67108864 `
    -Description "WN22-CC-000710: Application log size (64 MB minimum)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
    -Name "MaxSize" -Value 67108864 -Type DWord `
    -Description "WN22-CC-000710: Application log max size policy"

# Security Log
Write-Log "Configuring Security event log..." "INFO"

Set-EventLogSize -LogName "Security" -MaxSize 1073741824 `
    -Description "WN22-CC-000720: Security log size (1024 MB minimum)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -Name "MaxSize" -Value 1073741824 -Type DWord `
    -Description "WN22-CC-000720: Security log max size policy"

# System Log
Write-Log "Configuring System event log..." "INFO"

Set-EventLogSize -LogName "System" -MaxSize 67108864 `
    -Description "WN22-CC-000730: System log size (64 MB minimum)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
    -Name "MaxSize" -Value 67108864 -Type DWord `
    -Description "WN22-CC-000730: System log max size policy"

# PowerShell Operational Log
Write-Log "Configuring PowerShell event log..." "INFO"

Set-EventLogSize -LogName "Microsoft-Windows-PowerShell/Operational" -MaxSize 67108864 `
    -Description "WN22-CC-000740: PowerShell Operational log size (64 MB minimum)"

# Application and Services Logs
Write-Log "Configuring additional operational logs..." "INFO"

$operationalLogs = @(
    "Microsoft-Windows-TaskScheduler/Operational"
    "Microsoft-Windows-Windows Defender/Operational"
    "Microsoft-Windows-WinRM/Operational"
)

foreach ($log in $operationalLogs) {
    try {
        Set-EventLogSize -LogName $log -MaxSize 33554432 `
            -Description "Configure $log (32 MB)"
    }
    catch {
        Write-Log "WARN: Could not configure $log" "WARN"
    }
}

# Event log retention
Write-Log "Configuring event log retention..." "INFO"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" `
    -Name "Retention" -Value 0 -Type DWord `
    -Description "WN22-CC-000750: Application log - Overwrite as needed"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
    -Name "Retention" -Value 0 -Type DWord `
    -Description "WN22-CC-000760: Security log - Overwrite as needed"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" `
    -Name "Retention" -Value 0 -Type DWord `
    -Description "WN22-CC-000770: System log - Overwrite as needed"

# Enable Critical/Warning/Error logging
Write-Log "Verifying event log services..." "INFO"

$eventLogService = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
if ($eventLogService) {
    if ($eventLogService.Status -ne "Running") {
        Write-Log "WARN: Windows Event Log service is not running" "WARN"
    } else {
        Write-Log "SUCCESS: Windows Event Log service is running" "SUCCESS"
    }
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 7 Completed: Event Logs" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
