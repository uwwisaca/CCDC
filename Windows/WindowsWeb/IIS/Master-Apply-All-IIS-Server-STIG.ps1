<#
.SYNOPSIS
    Master script to orchestrate all IIS 10.0 Server STIG modules
.DESCRIPTION
    Runs IIS 10.0 Server STIG configuration modules in sequence
    Based on U_MS_IIS_10-0_Server_V3R6_Manual_STIG
.PARAMETER Module
    Specify individual module number (1-5) to run, or omit to run all
.PARAMETER WhatIf
    Preview changes without applying them
.EXAMPLE
    .\Master-Apply-All-IIS-Server-STIG.ps1
    Run all IIS Server STIG modules
.EXAMPLE
    .\Master-Apply-All-IIS-Server-STIG.ps1 -Module 1
    Run only logging configuration module
.EXAMPLE
    .\Master-Apply-All-IIS-Server-STIG.ps1 -WhatIf
    Preview all changes without applying
.NOTES
    Version: 1.0
    Date: February 12, 2026
    Requires: IIS 10.0, WebAdministration PowerShell module
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateRange(1,5)]
    [int]$Module,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MasterLog = "C:\Windows\Logs\STIG-IIS-Server-Master-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $MasterLog -Value $logMessage
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

# Module definitions
$modules = @(
    @{Number=1; Name="Logging Configuration"; Script="01-IIS-Server-Logging.ps1"},
    @{Number=2; Name="Authentication"; Script="02-IIS-Server-Authentication.ps1"; Status="Not Implemented"},
    @{Number=3; Name="Session Security"; Script="03-IIS-Server-Session-Security.ps1"; Status="Not Implemented"},
    @{Number=4; Name="Modules & Features"; Script="04-IIS-Server-Modules-Features.ps1"; Status="Not Implemented"},
    @{Number=5; Name="Directory Browsing"; Script="05-IIS-Server-Directory-Browsing.ps1"; Status="Not Implemented"}
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  IIS SERVER STIG MASTER CONFIGURATION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "[WHATIF MODE] - No changes will be applied`n" -ForegroundColor Yellow
}

# Verify prerequisites
Write-Log "Checking prerequisites..." "INFO"

if (!(Get-WindowsFeature -Name Web-Server).Installed) {
    Write-Log "IIS is not installed" "ERROR"
    throw "Please install IIS (Web-Server feature)"
}

if (!(Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Log "WebAdministration module not found" "ERROR"
    throw "Please install IIS management tools"
}

Write-Log "Prerequisites check passed" "SUCCESS"

# Determine which modules to run
if ($Module) {
    $modulesToRun = $modules | Where-Object { $_.Number -eq $Module }
}
else {
    $modulesToRun = $modules
}

# Execute modules
$successCount = 0
$failCount = 0
$skipCount = 0

foreach ($mod in $modulesToRun) {
    $scriptPath = Join-Path $ScriptDir $mod.Script
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Module $($mod.Number): $($mod.Name)" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    Write-Log "Starting Module $($mod.Number): $($mod.Name)" "INFO"
    
    if ($mod.Status -eq "Not Implemented") {
        Write-Host "SKIPPED: Module not yet implemented" -ForegroundColor Yellow
        Write-Host "Refer to DNS-AD-IIS-STIG-MODULES.md for implementation details`n" -ForegroundColor Yellow
        Write-Log "Module $($mod.Number) skipped: Not yet implemented" "WARN"
        $skipCount++
        continue
    }
    
    if (!(Test-Path $scriptPath)) {
        Write-Host "ERROR: Module script not found: $scriptPath`n" -ForegroundColor Red
        Write-Log "Module $($mod.Number) failed: Script not found" "ERROR"
        $failCount++
        continue
    }
    
    try {
        if ($WhatIf) {
            & $scriptPath -WhatIf
        }
        else {
            & $scriptPath
        }
        
        Write-Log "Module $($mod.Number) completed successfully" "SUCCESS"
        $successCount++
    }
    catch {
        Write-Host "ERROR executing module: $_`n" -ForegroundColor Red
        Write-Log "Module $($mod.Number) failed: $_" "ERROR"
        $failCount++
        
        $continue = Read-Host "Continue with remaining modules? (yes/no)"
        if ($continue -ne "yes") { break }
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Modules succeeded: $successCount" -ForegroundColor Green
if ($skipCount -gt 0) {
    Write-Host "Modules skipped: $skipCount (not yet implemented)" -ForegroundColor Yellow
}
if ($failCount -gt 0) {
    Write-Host "Modules failed: $failCount" -ForegroundColor Red
}

Write-Host "`nMaster log file: $MasterLog" -ForegroundColor Cyan

Write-Host "`nIMPORTANT POST-CONFIGURATION TASKS:" -ForegroundColor Yellow
Write-Host "1. Configure per-site STIG settings (use Master-Apply-All-IIS-Site-STIG.ps1)" -ForegroundColor Yellow
Write-Host "2. Review IIS logs regularly for security events" -ForegroundColor Yellow
Write-Host "3. Configure SSL/TLS certificates for all sites" -ForegroundColor Yellow
Write-Host "4. Remove or secure default IIS files and directories" -ForegroundColor Yellow
Write-Host "5. Implement Web Application Firewall (WAF) if available" -ForegroundColor Yellow
Write-Host "6. Test website functionality after hardening" -ForegroundColor Yellow
Write-Host "`n"

Write-Log "Master script completed: $successCount succeeded, $skipCount skipped, $failCount failed" "INFO"
