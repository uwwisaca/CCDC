# Deploy Wazuh Agents to All CCDC Windows Hosts
# Run from Windows Server 2019 AD/DNS (172.20.240.102)
# Version: 1.0
# Date: January 30, 2026

param(
    [string]$WazuhManager = "172.20.242.20",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$LogDir = ".\Logs"
$LogFile = "$LogDir\deploy-wazuh-agents-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Create log directory
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Level, [string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        default { Write-Host $logMessage }
    }
}

Write-Log INFO "========================================"
Write-Log INFO "Wazuh Agent Bulk Deployment"
Write-Log INFO "Wazuh Manager: $WazuhManager"
Write-Log INFO "Dry Run: $DryRun"
Write-Log INFO "========================================"

# CCDC Windows hosts
$windowsHosts = @(
    @{Name = "Windows11Wks"; IP = "172.20.240.100"},
    @{Name = "Server2019ADDNS"; IP = "172.20.240.102"},
    @{Name = "Server2019Web"; IP = "172.20.240.101"},
    @{Name = "Server2022FTP"; IP = "172.20.240.104"}
)

Write-Log INFO "Target hosts: $($windowsHosts.Count)"
foreach ($host in $windowsHosts) {
    Write-Log INFO "  - $($host.Name) ($($host.IP))"
}

if ($DryRun) {
    Write-Log WARN "DRY RUN - No agents will be installed"
    Write-Log INFO "Commands that would be executed:"
    foreach ($targetHost in $windowsHosts) {
        Write-Log INFO "  Invoke-Command -ComputerName $($targetHost.IP) -FilePath .\install-wazuh-agent-windows.ps1 -ArgumentList '$WazuhManager', '$($targetHost.Name)'"
    }
    exit 0
}

# Test connectivity to Wazuh Manager
Write-Log INFO "Testing connectivity to Wazuh Manager..."
if (Test-Connection -ComputerName $WazuhManager -Count 2 -Quiet) {
    Write-Log SUCCESS "Wazuh Manager is reachable"
} else {
    Write-Log ERROR "Cannot reach Wazuh Manager at $WazuhManager"
    exit 1
}

# Deploy to each host
$successCount = 0
$failCount = 0

foreach ($targetHost in $windowsHosts) {
    Write-Log INFO ""
    Write-Log INFO "Deploying to $($targetHost.Name) ($($targetHost.IP))..."
    
    # Test connectivity
    if (-not (Test-Connection -ComputerName $targetHost.IP -Count 2 -Quiet)) {
        Write-Log ERROR "Cannot reach $($targetHost.Name) at $($targetHost.IP)"
        $failCount++
        continue
    }
    
    try {
        # Copy installation script
        Write-Log INFO "Copying installation script to $($targetHost.Name)..."
        $session = New-PSSession -ComputerName $targetHost.IP -ErrorAction Stop
        Copy-Item -Path ".\install-wazuh-agent-windows.ps1" -Destination "C:\Windows\Temp\" -ToSession $session
        
        # Execute installation
        Write-Log INFO "Installing Wazuh agent on $($targetHost.Name)..."
        Invoke-Command -Session $session -ScriptBlock {
            param($Manager, $Name)
            & "C:\Windows\Temp\install-wazuh-agent-windows.ps1" -WazuhManager $Manager -AgentName $Name
        } -ArgumentList $WazuhManager, $targetHost.Name
        
        Remove-PSSession $session
        Write-Log SUCCESS "Wazuh agent deployed to $($targetHost.Name)"
        $successCount++
        
    } catch {
        Write-Log ERROR "Failed to deploy to $($targetHost.Name): $_"
        $failCount++
    }
    
    Start-Sleep -Seconds 2
}

Write-Log INFO ""
Write-Log INFO "========================================"
Write-Log INFO "Deployment Summary"
Write-Log INFO "========================================"
Write-Log INFO "Total hosts: $($windowsHosts.Count)"
Write-Log SUCCESS "Successful: $successCount"
if ($failCount -gt 0) {
    Write-Log ERROR "Failed: $failCount"
}
Write-Log INFO ""
Write-Log INFO "Next steps:"
Write-Log INFO "1. Verify agents on Wazuh Manager:"
Write-Log INFO "   /var/ossec/bin/agent_control -l"
Write-Log INFO "2. Check alerts: tail -f /var/ossec/logs/alerts/alerts.log"
Write-Log INFO "3. View in Splunk (if integrated)"
Write-Log INFO ""
Write-Log INFO "Log file: $LogFile"
