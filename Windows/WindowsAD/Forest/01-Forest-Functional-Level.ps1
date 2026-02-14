<#
.SYNOPSIS
    AD Forest STIG - Module 1: Functional Level and Features
.DESCRIPTION
    Checks forest functional level and enables AD Recycle Bin
    Based on U_Active_Directory_Forest_V3R2_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Forest-Module01-FunctionalLevel-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Forest-Module01-FunctionalLevel-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "AD Forest Module 1: Functional Level" "INFO"
Write-Log "========================================" "INFO"

Import-Module ActiveDirectory

$forest = Get-ADForest
$rootDomain = Get-ADDomain -Identity $forest.RootDomain

Write-Log "Forest: $($forest.Name)" "INFO"
Write-Log "Forest Functional Level: $($forest.ForestMode)" "INFO"
Write-Log "Root Domain: $($forest.RootDomain)" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $forest | Export-Clixml "$BackupDir\ForestSettings.xml"
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# WN19-AF-000010: Forest functional level
Write-Log "Checking forest functional level..." "INFO"

if ($forest.ForestMode -lt "Windows2016Forest") {
    Write-Log "WARNING: Forest functional level below Windows Server 2016" "WARN"
    Write-Log "Current: $($forest.ForestMode)" "WARN"
    Write-Log "Recommended: Raise to Windows2016Forest or higher" "WARN"
    Write-Log "Command: Set-ADForestMode -Identity $($forest.Name) -ForestMode Windows2016Forest" "WARN"
    Write-Log "WARNING: This operation is irreversible and requires all DCs at 2016 level" "WARN"
}
else {
    Write-Log "Forest functional level is compliant: $($forest.ForestMode)" "SUCCESS"
}

# WN19-AF-000040: AD Recycle Bin
Write-Log "Checking AD Recycle Bin status..." "INFO"

$recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"}
if ($recycleBinFeature.EnabledScopes.Count -eq 0) {
    Write-Log "AD Recycle Bin is NOT enabled" "WARN"
    
    if ($WhatIf) {
        Write-Log "[WHATIF] Would enable AD Recycle Bin" "INFO"
    }
    else {
        $response = Read-Host "Enable AD Recycle Bin? This operation is irreversible (yes/no)"
        if ($response -eq "yes") {
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
                -Scope ForestOrConfigurationSet `
                -Target $forest.Name -Confirm:$false
            Write-Log "SUCCESS: AD Recycle Bin enabled" "SUCCESS"
        }
        else {
            Write-Log "AD Recycle Bin enablement skipped by user" "WARN"
        }
    }
}
else {
    Write-Log "AD Recycle Bin is enabled" "SUCCESS"
}

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 1 Completed: Functional Level" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
