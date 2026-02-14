<#
.SYNOPSIS
    IIS 10.0 Server STIG - Module 1: Logging Configuration
.DESCRIPTION
    Configures IIS server-level logging settings
    Based on U_MS_IIS_10-0_Server_V3R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-IIS-Server-Module01-Logging-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\IIS-Server-Module01-Logging-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "IIS Server Module 1: Logging" "INFO"
Write-Log "========================================" "INFO"

# Check if IIS is installed
if (!(Get-WindowsFeature -Name Web-Server).Installed) {
    Write-Log "IIS is not installed" "ERROR"
    exit 1
}

Import-Module WebAdministration

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    
    # Backup IIS configuration
    $config = Get-WebConfiguration -Filter /system.applicationHost/sites/siteDefaults/logFile
    $config | Export-Clixml "$BackupDir\LogFileConfig.xml"
    
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# V-218759: Configure logging format to W3C
Write-Log "Configuring log file format..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would set log format to W3C" "INFO"
}
else {
    Set-WebConfigurationProperty -Filter /system.applicationHost/sites/siteDefaults/logFile `
        -PSPath IIS:\ -Name logFormat -Value W3C
    
    Write-Log "SUCCESS: Log format set to W3C" "SUCCESS"
}

# V-218760: Configure log fields
Write-Log "Configuring log fields..." "INFO"

$requiredFields = @(
    "Date", "Time", "ClientIP", "UserName", "Method", 
    "UriStem", "UriQuery", "HttpStatus", "HttpSubStatus", 
    "Win32Status", "TimeTaken", "ServerIP", "UserAgent", 
    "Referer", "Host"
)

if ($WhatIf) {
    Write-Log "[WHATIF] Would configure log fields: $($requiredFields -join ', ')" "INFO"
}
else {
    Set-WebConfigurationProperty -Filter /system.applicationHost/sites/siteDefaults/logFile `
        -PSPath IIS:\ -Name logExtFileFlags `
        -Value "Date,Time,ClientIP,UserName,Method,UriStem,UriQuery,HttpStatus,HttpSubStatus,Win32Status,TimeTaken,ServerIP,UserAgent,Referer,Host"
    
    Write-Log "SUCCESS: Log fields configured" "SUCCESS"
}

# V-218761: ETW logging
Write-Log "Enabling ETW logging..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would enable ETW logging" "INFO"
}
else {
    Set-WebConfigurationProperty -Filter /system.applicationHost/sites/siteDefaults/logFile `
        -PSPath IIS:\ -Name logTargetW3C -Value "File,ETW"
    
    Write-Log "SUCCESS: ETW logging enabled" "SUCCESS"
}

# Configure log directory
Write-Log "Configuring log directory..." "INFO"

$logDirectory = "C:\inetpub\logs\LogFiles"
if ($WhatIf) {
    Write-Log "[WHATIF] Would set log directory to $logDirectory" "INFO"
}
else {
    Set-WebConfigurationProperty -Filter /system.applicationHost/sites/siteDefaults/logFile `
        -PSPath IIS:\ -Name directory -Value $logDirectory
    
    Write-Log "SUCCESS: Log directory: $logDirectory" "SUCCESS"
}

# Configure log rollover
Write-Log "Configuring log rollover..." "INFO"

if ($WhatIf) {
    Write-Log "[WHATIF] Would set log rollover to daily" "INFO"
}
else {
    Set-WebConfigurationProperty -Filter /system.applicationHost/sites/siteDefaults/logFile `
        -PSPath IIS:\ -Name period -Value Daily
    
    Write-Log "SUCCESS: Log rollover set to daily" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 1 Completed: IIS Server Logging" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "WARN"
Write-Log "1. Configure log file permissions (Administrators only)" "WARN"
Write-Log "2. Implement log monitoring and SIEM integration" "WARN"
Write-Log "3. Configure log retention/archival policy" "WARN"
Write-Log "4. Review logs regularly for security events" "WARN"
