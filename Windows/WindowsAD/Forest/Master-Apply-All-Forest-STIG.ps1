<#
.SYNOPSIS
    Master script to orchestrate all AD Forest STIG modules
.DESCRIPTION
    Runs AD Forest STIG configuration modules in sequence
    Based on U_Active_Directory_Forest_V3R2_Manual_STIG
.PARAMETER Module
    Specify individual module number (1-6) to run, or omit to run all
.PARAMETER WhatIf
    Preview changes without applying them
.EXAMPLE
    .\Master-Apply-All-Forest-STIG.ps1
    Run all AD Forest STIG modules
.EXAMPLE
    .\Master-Apply-All-Forest-STIG.ps1 -Module 1
    Run only functional level module
.EXAMPLE
    .\Master-Apply-All-Forest-STIG.ps1 -WhatIf
    Preview all changes without applying
.NOTES
    Version: 1.0
    Date: February 12, 2026
    Requires: Active Directory PowerShell module, Schema/Enterprise Admin rights
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateRange(1,6)]
    [int]$Module,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MasterLog = "C:\Windows\Logs\STIG-Forest-Master-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
    @{Number=1; Name="Functional Level & AD Recycle Bin"; Script="01-Forest-Functional-Level.ps1"},
    @{Number=2; Name="Privileged Groups"; Script="02-Forest-Privileged-Groups.ps1"; Status="Not Implemented"},
    @{Number=3; Name="FSMO Roles"; Script="03-Forest-FSMO-Roles.ps1"; Status="Not Implemented"},
    @{Number=4; Name="Trusts"; Script="04-Forest-Trusts.ps1"; Status="Not Implemented"},
    @{Number=5; Name="Sites & Replication"; Script="05-Forest-Sites-Replication.ps1"; Status="Not Implemented"},
    @{Number=6; Name="Infrastructure"; Script="06-Forest-Infrastructure.ps1"; Status="Not Implemented"}
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD FOREST STIG MASTER CONFIGURATION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "[WHATIF MODE] - No changes will be applied`n" -ForegroundColor Yellow
}

# Verify prerequisites
Write-Log "Checking prerequisites..." "INFO"

if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module not found" "ERROR"
    throw "Please install RSAT-AD-PowerShell feature"
}

# Verify domain controller
$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
if (!$isDC) {
    Write-Log "This computer is not a domain controller" "WARN"
    $continue = Read-Host "Continue anyway? (yes/no)"
    if ($continue -ne "yes") { exit }
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
Write-Host "1. Review Schema Admins and Enterprise Admins membership" -ForegroundColor Yellow
Write-Host "2. Verify FSMO role holders are operational" -ForegroundColor Yellow
Write-Host "3. Review external trust configurations" -ForegroundColor Yellow
Write-Host "4. Validate site topology and replication health" -ForegroundColor Yellow
Write-Host "5. Ensure time synchronization is working correctly" -ForegroundColor Yellow
Write-Host "6. Monitor AD Recycle Bin for deleted objects" -ForegroundColor Yellow
Write-Host "`n"

Write-Log "Master script completed: $successCount succeeded, $skipCount skipped, $failCount failed" "INFO"
