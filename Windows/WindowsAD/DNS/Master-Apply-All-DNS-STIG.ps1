<#
.SYNOPSIS
    DNS Server STIG Master Script
.DESCRIPTION
    Orchestrates all DNS Server STIG modules for comprehensive DNS hardening
    Based on U_Domain_Name_System_V4R2_Manual_SRG
.NOTES
    Version: 1.0
    Date: February 12, 2026
    
.PARAMETER Module
    Run a specific module number (1-5)
    
.PARAMETER WhatIf
    Show what would be done without making changes
    
.EXAMPLE
    .\Master-Apply-All-DNS-STIG.ps1
    Run all DNS STIG modules
    
.EXAMPLE
    .\Master-Apply-All-DNS-STIG.ps1 -Module 2
    Run only module 2 (Zone Configuration)
    
.EXAMPLE
    .\Master-Apply-All-DNS-STIG.ps1 -WhatIf
    Preview changes without applying them
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,5)]
    [int]$Module,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MasterLogFile = "C:\Windows\Logs\STIG-DNS-Master-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
        
        Write-MasterLog "SUCCESS: Module $ModuleNumber completed" "SUCCESS"
        return $true
    }
    catch {
        Write-MasterLog "ERROR: Module $ModuleNumber failed: $_" "ERROR"
        return $false
    }
}

# Check DNS server feature
if (!(Get-WindowsFeature -Name DNS).Installed) {
    Write-MasterLog "DNS Server feature is not installed. Cannot proceed." "ERROR"
    exit 1
}

# Main execution
Write-MasterLog "========================================" "INFO"
Write-MasterLog "DNS Server STIG Master Script" "INFO"
Write-MasterLog "========================================" "INFO"
Write-MasterLog "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
Write-MasterLog "DNS Server: $env:COMPUTERNAME" "INFO"
Write-MasterLog "User: $env:USERNAME" "INFO"

if ($WhatIf) {
    Write-MasterLog "RUNNING IN WHATIF MODE - No changes will be made" "WARN"
}

if ($Module) {
    Write-MasterLog "Single module mode: Running module $Module only" "INFO"
}

Write-MasterLog "" "INFO"

# Define modules
$modules = @(
    @{Number=1; Name="Logging Configuration"; Script="01-DNS-Logging.ps1"},
    @{Number=2; Name="Zone Configuration"; Script="02-DNS-Zones.ps1"},
    @{Number=3; Name="Forwarders and Recursion"; Script="03-DNS-Forwarders-Recursion.ps1"},
    @{Number=4; Name="Security Settings"; Script="04-DNS-Security.ps1"},
    @{Number=5; Name="Backup Configuration"; Script="05-DNS-Backup.ps1"}
)

$successCount = 0
$failureCount = 0

# Execute modules
foreach ($mod in $modules) {
    # Skip if running single module and this isn't it
    if ($Module -and $mod.Number -ne $Module) {
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
Write-MasterLog "DNS STIG Application Summary" "INFO"
Write-MasterLog "========================================" "INFO"
Write-MasterLog "Successful modules: $successCount" "SUCCESS"
if ($failureCount -gt 0) {
    Write-MasterLog "Failed modules: $failureCount" "ERROR"
}
Write-MasterLog "Master log file: $MasterLogFile" "INFO"
Write-MasterLog "Individual module logs: C:\Windows\Logs\STIG-DNS-Module*.log" "INFO"
Write-MasterLog "Backups: C:\Windows\STIG-Backups\DNS-*" "INFO"
Write-MasterLog "Latest DNS backup: C:\DNSBackup\" "INFO"
Write-MasterLog "" "INFO"

# Important notes
Write-MasterLog "========================================" "WARN"
Write-MasterLog "CRITICAL POST-CONFIGURATION TASKS" "WARN"
Write-MasterLog "========================================" "WARN"
Write-MasterLog "1. Configure zone transfer allow list for each zone" "WARN"
Write-MasterLog "2. Sign zones with DNSSEC where required" "WARN"
Write-MasterLog "3. Configure forwarders to approved DNS servers (if recursive)" "WARN"
Write-MasterLog "4. Disable recursion if this is authoritative-only server" "WARN"
Write-MasterLog "5. Configure listen addresses (don't expose on all interfaces)" "WARN"
Write-MasterLog "6. Configure Windows Firewall to restrict DNS access" "WARN"
Write-MasterLog "7. Verify file and registry permissions on DNS folders" "WARN"
Write-MasterLog "8. Test DNS resolution from authorized clients" "WARN"
Write-MasterLog "9. Monitor DNS event logs and C:\Windows\System32\dns\dns.log" "WARN"
Write-MasterLog "10. Schedule regular automated backups" "WARN"
Write-MasterLog "11. Test DNS backup restore procedures" "WARN"
Write-MasterLog "" "INFO"

Write-MasterLog "DNS STIG application completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "SUCCESS"
Write-MasterLog "" "INFO"
Write-MasterLog "Review individual module logs for detailed information and warnings." "INFO"
