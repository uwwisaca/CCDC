<#
.SYNOPSIS
    Windows 11 24H2 STIG Master Script
.DESCRIPTION
    Orchestrates all Windows 11 24H2 STIG modules for comprehensive hardening
    Based on U_MS_Windows_11_V2R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
    
.PARAMETER Module
    Run a specific module number (1-8)
    
.PARAMETER SkipFirewall
    Skip the Windows Firewall configuration module (08)
    
.PARAMETER NoReboot
    Skip the reboot prompt at the end
    
.PARAMETER WhatIf
    Show what would be done without making changes
    
.EXAMPLE
    .\Master-Apply-All-STIG.ps1
    Run all STIG modules
    
.EXAMPLE
    .\Master-Apply-All-STIG.ps1 -Module 3
    Run only module 3 (Security Options)
    
.EXAMPLE
    .\Master-Apply-All-STIG.ps1 -SkipFirewall
    Run all modules except Windows Firewall
    
.EXAMPLE
    .\Master-Apply-All-STIG.ps1 -WhatIf
    Preview changes without applying them
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,8)]
    [int]$Module,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipFirewall,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoReboot,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MasterLogFile = "C:\Windows\Logs\STIG-Master-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-MasterLog {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $MasterLogFile -Value $logMessage
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "HEADER" { 
            Write-Host ""
            Write-Host "===========================================" -ForegroundColor Cyan
            Write-Host $Message -ForegroundColor Cyan
            Write-Host "===========================================" -ForegroundColor Cyan
        }
        default { Write-Host $logMessage }
    }
}

function Invoke-STIGModule {
    param(
        [int]$ModuleNumber,
        [string]$ModuleName,
        [string]$ScriptName
    )
    
    Write-MasterLog "Executing Module $ModuleNumber : $ModuleName" "HEADER"
    
    $scriptPath = Join-Path $ScriptDir $ScriptName
    
    if (!(Test-Path $scriptPath)) {
        Write-MasterLog "ERROR: Script not found: $scriptPath" "ERROR"
        return $false
    }
    
    try {
        if ($WhatIf) {
            & $scriptPath -WhatIf
        }
        else {
            & $scriptPath
        }
        
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            Write-MasterLog "WARN: Module $ModuleNumber completed with warnings" "WARN"
            return $true
        }
        
        Write-MasterLog "SUCCESS: Module $ModuleNumber completed" "SUCCESS"
        return $true
    }
    catch {
        Write-MasterLog "ERROR: Module $ModuleNumber failed: $_" "ERROR"
        return $false
    }
}

# Main execution
Write-MasterLog "========================================" "INFO"
Write-MasterLog "Windows 11 24H2 STIG Master Script" "INFO"
Write-MasterLog "========================================" "INFO"
Write-MasterLog "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
Write-MasterLog "Computer: $env:COMPUTERNAME" "INFO"
Write-MasterLog "User: $env:USERNAME" "INFO"

if ($WhatIf) {
    Write-MasterLog "RUNNING IN WHATIF MODE - No changes will be made" "WARN"
}

if ($Module) {
    Write-MasterLog "Single module mode: Running module $Module only" "INFO"
}

if ($SkipFirewall) {
    Write-MasterLog "Firewall module will be skipped" "INFO"
}

Write-MasterLog "" "INFO"

# Define modules
$modules = @(
    @{Number=1; Name="Account Policies"; Script="01-Account-Policies.ps1"},
    @{Number=2; Name="Audit Policies"; Script="02-Audit-Policies.ps1"},
    @{Number=3; Name="Security Options"; Script="03-Security-Options.ps1"},
    @{Number=4; Name="Network Security"; Script="04-Network-Security.ps1"},
    @{Number=5; Name="Windows Defender"; Script="05-Windows-Defender.ps1"},
    @{Number=6; Name="RDS and PowerShell"; Script="06-RDS-PowerShell.ps1"},
    @{Number=7; Name="Event Logs"; Script="07-Event-Logs.ps1"},
    @{Number=8; Name="Windows Firewall and Services"; Script="08-Windows-Firewall-Services.ps1"}
)

$successCount = 0
$failureCount = 0

# Execute modules
foreach ($mod in $modules) {
    # Skip if running single module and this isn't it
    if ($Module -and $mod.Number -ne $Module) {
        continue
    }
    
    # Skip firewall if requested
    if ($SkipFirewall -and $mod.Number -eq 8) {
        Write-MasterLog "Skipping Module $($mod.Number): $($mod.Name) (--SkipFirewall)" "INFO"
        continue
    }
    
    $result = Invoke-STIGModule -ModuleNumber $mod.Number -ModuleName $mod.Name -ScriptName $mod.Script
    
    if ($result) {
        $successCount++
    }
    else {
        $failureCount++
    }
    
    Start-Sleep -Seconds 2
}

# Summary
Write-MasterLog "" "INFO"
Write-MasterLog "========================================" "INFO"
Write-MasterLog "STIG Application Summary" "INFO"
Write-MasterLog "========================================" "INFO"
Write-MasterLog "Successful modules: $successCount" "SUCCESS"
if ($failureCount -gt 0) {
    Write-MasterLog "Failed modules: $failureCount" "ERROR"
}
Write-MasterLog "Master log file: $MasterLogFile" "INFO"
Write-MasterLog "Individual module logs: C:\Windows\Logs\STIG-Module*.log" "INFO"
Write-MasterLog "Backups: C:\Windows\STIG-Backups\" "INFO"
Write-MasterLog "" "INFO"

# Important notes
Write-MasterLog "========================================" "WARN"
Write-MasterLog "IMPORTANT POST-CONFIGURATION STEPS" "WARN"
Write-MasterLog "========================================" "WARN"
Write-MasterLog "1. Review event logs for any errors" "WARN"
Write-MasterLog "2. Verify Windows Firewall rules allow required services (FTP, RDP, etc.)" "WARN"
Write-MasterLog "3. Test application functionality before deploying to production" "WARN"
Write-MasterLog "4. For workstation use, review and adjust firewall rules for required applications" "WARN"
Write-MasterLog "5. Update Group Policy: Run 'gpupdate /force' after reboot" "WARN"
Write-MasterLog "" "INFO"

# Reboot prompt
if (!$NoReboot -and !$WhatIf) {
    Write-MasterLog "A system reboot is recommended to apply all settings" "WARN"
    $response = Read-Host "Reboot now? (yes/no)"
    if ($response -eq "yes" -or $response -eq "y") {
        Write-MasterLog "Initiating system reboot..." "INFO"
        Restart-Computer -Force
    }
    else {
        Write-MasterLog "Reboot postponed. Please reboot manually to complete STIG application." "WARN"
    }
}
elseif ($WhatIf) {
    Write-MasterLog "[WHATIF] Would prompt for system reboot" "INFO"
}
else {
    Write-MasterLog "Reboot skipped (--NoReboot specified). Please reboot manually." "INFO"
}

Write-MasterLog "Script execution completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "SUCCESS"
