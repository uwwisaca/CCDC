# PowerShell Script to Apply Palo Alto STIG via SSH
# Connects to Palo Alto firewall and applies STIG hardening commands
# Version: 1.0
# Date: January 30, 2026
#
# NOTE: Palo Alto (172.20.242.150) is on the 172.20.242.x network
# RECOMMENDED: Deploy from Ubuntu Ecom Server (172.20.242.30) - same network segment
# Use ./deploy-paloalto-stig.sh instead for better reliability
#
# This PowerShell script is provided as an alternative if Windows deployment is needed
#
# Usage: .\Deploy-PaloAlto-STIG.ps1 -HostIP "172.20.242.150" -Username "admin"

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$HostIP,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [string]$Password,
    
    [string]$ConfigFile = ".\PanOS 11.0.2\PAN-STIG-Configuration-Guide.txt",
    
    [switch]$DryRun,
    
    [switch]$UseXML
)

$ErrorActionPreference = "Continue"
$LogFile = ".\Logs\PaloAlto-Deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Create logs directory
if (!(Test-Path ".\Logs")) {
    New-Item -Path ".\Logs" -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
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

Write-Log "========================================"
Write-Log "Palo Alto STIG Deployment via SSH"
Write-Log "Target: $HostIP"
Write-Log "========================================"

# Check if Posh-SSH module is installed
if (!(Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Log "Posh-SSH module not found. Installing..." "WARN"
    Install-Module -Name Posh-SSH -Force -Scope CurrentUser
}

Import-Module Posh-SSH

# Get password if not provided
if (!$Password) {
    $SecurePassword = Read-Host "Enter password for $Username" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

# Create credential object
$SecurePasswordObj = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePasswordObj)

# Test connectivity
Write-Log "Testing connectivity to $HostIP..." "INFO"
if (!(Test-Connection -ComputerName $HostIP -Count 2 -Quiet)) {
    Write-Log "Cannot reach host: $HostIP" "ERROR"
    exit 1
}
Write-Log "Host is reachable" "SUCCESS"

# Check if XML config file exists
$xmlConfigFile = ".\PanOS 11.0.2\22.xml"
if ($UseXML -and (Test-Path $xmlConfigFile)) {
    Write-Log "Using XML configuration file: $xmlConfigFile" "INFO"
    # TODO: Parse and import XML configuration
    Write-Log "XML import feature - manual import required via web UI" "WARN"
    Write-Log "To import XML: Device > Setup > Operations > Import Named Configuration Snapshot" "WARN"
}

# Palo Alto STIG Commands (CLI-based)
$paloCommands = @"
# Enter configuration mode
configure

# ========================================
# Password Policy
# ========================================
set mgt-config password-complexity enabled yes
set mgt-config password-complexity minimum-length 15
set mgt-config password-complexity minimum-uppercase-letters 1
set mgt-config password-complexity minimum-lowercase-letters 1
set mgt-config password-complexity minimum-numeric-letters 1
set mgt-config password-complexity minimum-special-characters 1
set mgt-config password-complexity password-change-period-block 5
set mgt-config password-complexity password-change-on-first-login yes
set mgt-config password-complexity expiration-period 60
set mgt-config failed-attempts 3
set mgt-config lockout-time 15

# ========================================
# Session Timeout
# ========================================
set deviceconfig setting session timeout 15

# ========================================
# Banner
# ========================================
set deviceconfig system login-banner "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS you consent to monitoring and recording. Unauthorized use may result in criminal and/or civil penalties."

# ========================================
# NTP Configuration
# ========================================
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 172.16.101.1
set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key
set deviceconfig system ntp-servers primary-ntp-server algorithm sha1
set deviceconfig system ntp-servers primary-ntp-server authentication-key ChangeThisNTPKey123
set deviceconfig system timezone US/Eastern

# ========================================
# Logging Configuration
# ========================================
set shared log-settings syslog STIG-SYSLOG server SIEM-Server server 172.20.242.30
set shared log-settings syslog STIG-SYSLOG server SIEM-Server transport UDP
set shared log-settings syslog STIG-SYSLOG server SIEM-Server port 514
set shared log-settings syslog STIG-SYSLOG server SIEM-Server format BSD
set shared log-settings syslog STIG-SYSLOG server SIEM-Server facility LOG_USER

# ========================================
# Management Interface Access
# ========================================
set deviceconfig system permitted-ip 172.20.240.0/24 description "Management Network"
set deviceconfig system service disable-http yes
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-snmp yes

# ========================================
# SSL/TLS Settings
# ========================================
set deviceconfig setting ssl-tls-service-profile STIG-TLS protocol-settings min-version tls1-2
set deviceconfig setting ssl-tls-service-profile STIG-TLS protocol-settings max-version tls1-3
set deviceconfig setting ssl-tls-service-profile STIG-TLS certificate management-cert
set deviceconfig setting management ssl-tls-service-profile STIG-TLS

# ========================================
# Security Zones (Basic Setup)
# ========================================
set zone trust network layer3 ethernet1/1
set zone untrust network layer3 ethernet1/2
set zone dmz network layer3 ethernet1/3

# ========================================
# Commit changes
# ========================================
commit description "STIG compliance configuration"
"@

if ($DryRun) {
    Write-Log "DRY RUN MODE - Commands that would be executed:" "WARN"
    $paloCommands -split "`n" | ForEach-Object {
        Write-Log $_ "INFO"
    }
    Write-Log "Dry run complete. No changes made." "SUCCESS"
    exit 0
}

try {
    # Establish SSH session
    Write-Log "Establishing SSH connection to $HostIP..." "INFO"
    $SSHSession = New-SSHSession -ComputerName $HostIP -Credential $Credential -AcceptKey -ConnectionTimeout 30
    
    if ($SSHSession) {
        Write-Log "SSH session established" "SUCCESS"
        
        # Create SSH shell stream
        $Stream = New-SSHShellStream -SessionId $SSHSession.SessionId
        Start-Sleep -Seconds 2
        
        # Read initial prompt
        $initialOutput = $Stream.Read()
        Write-Log "Connected to Palo Alto firewall" "SUCCESS"
        
        # Send commands
        $commandList = $paloCommands -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
        
        $totalCommands = $commandList.Count
        $currentCommand = 0
        
        foreach ($command in $commandList) {
            $command = $command.Trim()
            if ([string]::IsNullOrWhiteSpace($command)) { continue }
            
            $currentCommand++
            Write-Log "[$currentCommand/$totalCommands] Executing: $command" "INFO"
            $Stream.WriteLine($command)
            Start-Sleep -Milliseconds 800
            
            # Read output
            $output = $Stream.Read()
            if ($output -match "error|invalid|failed|unknown command") {
                Write-Log "Command may have failed: $command" "WARN"
                Write-Log "Output: $output" "WARN"
            }
            
            # Check if commit command - wait longer
            if ($command -match "^commit") {
                Write-Log "Committing changes - this may take 30-60 seconds..." "INFO"
                Start-Sleep -Seconds 45
                $commitOutput = $Stream.Read()
                Write-Log "Commit output: $commitOutput" "INFO"
                
                if ($commitOutput -match "commit succeeded") {
                    Write-Log "Configuration committed successfully" "SUCCESS"
                }
                elseif ($commitOutput -match "commit failed") {
                    Write-Log "Commit failed - review errors" "ERROR"
                }
            }
        }
        
        # Final read
        Start-Sleep -Seconds 2
        $finalOutput = $Stream.Read()
        Write-Log "Final output: $finalOutput" "INFO"
        
        Write-Log "All commands executed" "SUCCESS"
        
        # Close stream and session
        $Stream.Close()
        Remove-SSHSession -SessionId $SSHSession.SessionId | Out-Null
        Write-Log "SSH session closed" "SUCCESS"
    }
    else {
        Write-Log "Failed to establish SSH session" "ERROR"
        exit 1
    }
}
catch {
    Write-Log "Error during SSH execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    
    # Cleanup
    if ($SSHSession) {
        Remove-SSHSession -SessionId $SSHSession.SessionId -ErrorAction SilentlyContinue | Out-Null
    }
    exit 1
}

Write-Log ""
Write-Log "========================================"
Write-Log "Palo Alto STIG Deployment Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log ""
Write-Log "IMPORTANT NEXT STEPS:" "WARN"
Write-Log "1. Verify configuration via Web UI or CLI" "WARN"
Write-Log "2. Configure security policies (default deny rule)" "WARN"
Write-Log "3. Set up threat prevention profiles" "WARN"
Write-Log "4. Configure SSL decryption policies (if required)" "WARN"
Write-Log "5. Set up TACACS+ or RADIUS authentication" "WARN"
Write-Log "6. Configure GlobalProtect (if VPN needed)" "WARN"
Write-Log "7. Update content (Applications, Threats, WildFire)" "WARN"
Write-Log "8. Test logging to syslog server" "WARN"
Write-Log "9. Configure HA (if second firewall available)" "WARN"
Write-Log "10. Backup configuration to external location" "WARN"
Write-Log ""
Write-Log "To view configuration:" "INFO"
Write-Log "  show config running" "INFO"
Write-Log ""
Write-Log "To export configuration:" "INFO"
Write-Log "  scp export configuration to admin@172.20.242.30:/backups/paloalto-config.xml" "INFO"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
