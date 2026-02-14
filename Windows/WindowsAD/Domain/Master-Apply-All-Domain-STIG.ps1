<#
.SYNOPSIS
    Master script to orchestrate all AD Domain STIG modules
.DESCRIPTION
    Runs AD Domain STIG configuration modules in sequence
    Based on U_Active_Directory_Domain_V3R6_Manual_STIG
.PARAMETER Module
    Specify individual module number (1-7) to run, or omit to run all
.PARAMETER WhatIf
    Preview changes without applying them
.EXAMPLE
    .\Master-Apply-All-Domain-STIG.ps1
    Run all AD Domain STIG modules
.EXAMPLE
    .\Master-Apply-All-Domain-STIG.ps1 -Module 1
    Run only password policy module
.EXAMPLE
    .\Master-Apply-All-Domain-STIG.ps1 -WhatIf
    Preview all changes without applying
.NOTES
    Version: 1.0
    Date: February 12, 2026
    Requires: Active Directory PowerShell module
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateRange(1,7)]
    [int]$Module,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MasterLog = "C:\Windows\Logs\STIG-Domain-Master-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
    @{Number=1; Name="Password Policy"; Script="01-Domain-Password-Policy.ps1"},
    @{Number=2; Name="User Accounts"; Script="02-Domain-User-Accounts.ps1"; Status="Not Implemented"},
    @{Number=3; Name="LDAP Security"; Script="03-Domain-LDAP-Security.ps1"; Status="Not Implemented"},
    @{Number=4; Name="Service Accounts"; Script="04-Domain-Service-Accounts.ps1"; Status="Not Implemented"},
    @{Number=5; Name="Privileged Groups"; Script="05-Domain-Privileged-Groups.ps1"; Status="Not Implemented"},
    @{Number=6; Name="Built-in Accounts"; Script="06-Domain-Built-in-Accounts.ps1"; Status="Not Implemented"},
    @{Number=7; Name="Advanced Features"; Script="07-Domain-Advanced-Features.ps1"; Status="Not Implemented"}
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD DOMAIN STIG MASTER CONFIGURATION" -ForegroundColor Cyan
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
Write-Host "1. Configure Kerberos policy in Default Domain Policy GPO" -ForegroundColor Yellow
Write-Host "2. Review privileged group memberships" -ForegroundColor Yellow
Write-Host "3. Test user authentication and password changes" -ForegroundColor Yellow
Write-Host "4. Review service accounts and SPNs" -ForegroundColor Yellow
Write-Host "5. Enable audit logging for account management" -ForegroundColor Yellow
Write-Host "`n"

Write-Log "Master script completed: $successCount succeeded, $skipCount skipped, $failCount failed" "INFO"
