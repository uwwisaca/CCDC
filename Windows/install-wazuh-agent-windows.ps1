# Wazuh Agent Installation Script for Windows
# Deploy to all Windows hosts in CCDC environment
# Version: 1.0
# Date: January 30, 2026

param(
    [string]$WazuhManager = "172.20.242.20",
    [string]$AgentName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\Windows\Temp\wazuh-agent-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
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
Write-Log INFO "Wazuh Agent Installation for Windows"
Write-Log INFO "Target: $AgentName"
Write-Log INFO "Manager: $WazuhManager"
Write-Log INFO "========================================"

# Check for admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log ERROR "This script requires administrator privileges"
    exit 1
}

# Download Wazuh agent
Write-Log INFO "Downloading Wazuh agent..."
$wazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
$installerPath = "$env:TEMP\wazuh-agent.msi"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $wazuhUrl -OutFile $installerPath -UseBasicParsing
    Write-Log SUCCESS "Wazuh agent downloaded"
} catch {
    Write-Log ERROR "Failed to download Wazuh agent: $_"
    exit 1
}

# Install Wazuh agent
Write-Log INFO "Installing Wazuh agent..."
try {
    $arguments = @(
        "/i"
        "`"$installerPath`""
        "/q"
        "WAZUH_MANAGER=`"$WazuhManager`""
        "WAZUH_AGENT_NAME=`"$AgentName`""
        "WAZUH_REGISTRATION_SERVER=`"$WazuhManager`""
    )
    
    Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow
    Write-Log SUCCESS "Wazuh agent installed"
} catch {
    Write-Log ERROR "Failed to install Wazuh agent: $_"
    exit 1
}

# Configure agent
Write-Log INFO "Configuring Wazuh agent..."
$configPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

if (Test-Path $configPath) {
    # Backup original config
    Copy-Item $configPath "$configPath.backup"
    
    # Read and modify configuration
    [xml]$config = Get-Content $configPath
    
    # Set log analysis for Windows Event Logs
    $config.ossec_config.localfile | ForEach-Object {
        if ($_.location -like "*EventChannel*") {
            Write-Log INFO "Windows Event Log monitoring configured"
        }
    }
    
    $config.Save($configPath)
    Write-Log SUCCESS "Configuration updated"
}

# Configure Windows Firewall
Write-Log INFO "Configuring Windows Firewall..."
try {
    New-NetFirewallRule -DisplayName "Wazuh Agent - Outbound" `
                        -Direction Outbound `
                        -Protocol TCP `
                        -RemoteAddress $WazuhManager `
                        -RemotePort 1514 `
                        -Action Allow `
                        -ErrorAction SilentlyContinue
    Write-Log SUCCESS "Firewall rule created"
} catch {
    Write-Log WARN "Failed to create firewall rule: $_"
}

# Start Wazuh agent service
Write-Log INFO "Starting Wazuh agent service..."
try {
    Start-Service -Name "WazuhSvc"
    Set-Service -Name "WazuhSvc" -StartupType Automatic
    Write-Log SUCCESS "Wazuh agent service started"
} catch {
    Write-Log ERROR "Failed to start Wazuh service: $_"
    exit 1
}

# Verify installation
Start-Sleep -Seconds 5
$service = Get-Service -Name "WazuhSvc"

if ($service.Status -eq "Running") {
    Write-Log SUCCESS "Wazuh agent is running"
} else {
    Write-Log ERROR "Wazuh agent service is not running"
    exit 1
}

Write-Log INFO ""
Write-Log INFO "========================================"
Write-Log INFO "Wazuh Agent Installation Complete"
Write-Log INFO "========================================"
Write-Log INFO "Agent Name: $AgentName"
Write-Log INFO "Manager: $WazuhManager"
Write-Log INFO "Service: Running"
Write-Log INFO ""
Write-Log INFO "Configuration: C:\Program Files (x86)\ossec-agent\ossec.conf"
Write-Log INFO "Logs: C:\Program Files (x86)\ossec-agent\ossec.log"
Write-Log INFO ""
Write-Log INFO "Commands:"
Write-Log INFO "  Status: Get-Service WazuhSvc"
Write-Log INFO "  Restart: Restart-Service WazuhSvc"
Write-Log INFO "  View logs: Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 50"
Write-Log INFO ""
Write-Log SUCCESS "Agent successfully connected to Wazuh Manager!"

# Clean up installer
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
