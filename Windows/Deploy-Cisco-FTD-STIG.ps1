# PowerShell Script to Apply Cisco FTD STIG via SSH
# Connects to Cisco FTD/ASA and applies STIG hardening commands
# Version: 1.0
# Date: January 30, 2026
#
# Usage: .\Deploy-Cisco-FTD-STIG.ps1 -HostIP "172.20.240.200" -Username "admin"

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$HostIP,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [string]$Password,
    
    [string]$EnablePassword,
    
    [string]$ConfigFile = ".\Cisco FTD 7.2.9\FTD-STIG-Configuration-Guide.txt",
    
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"
$LogFile = ".\Logs\Cisco-FTD-Deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
Write-Log "Cisco FTD STIG Deployment via SSH"
Write-Log "Target: $HostIP"
Write-Log "========================================"

# Check if Posh-SSH module is installed
if (!(Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Log "Posh-SSH module not found. Installing..." "WARN"
    Install-Module -Name Posh-SSH -Force -Scope CurrentUser
}

Import-Module Posh-SSH

# Get credentials if not provided
if (!$Password) {
    $SecurePassword = Read-Host "Enter password for $Username" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if (!$EnablePassword) {
    $SecureEnablePassword = Read-Host "Enter enable password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureEnablePassword)
    $EnablePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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

# Cisco FTD STIG Commands
$ciscoCommands = @"
! Entering configuration mode
enable
$EnablePassword
configure terminal

! ========================================
! Password Policy Configuration
! ========================================
password-policy minimum-length 14
password-policy complexity enable
password-policy lifetime 60

! ========================================
! AAA Configuration
! ========================================
aaa authentication login-attempts max-failures 3
aaa authentication ssh console LOCAL

! ========================================
! Banner Configuration
! ========================================
banner motd You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS you consent to monitoring and recording. Unauthorized use may result in criminal and/or civil penalties.
banner login You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
banner exec Unauthorized access is prohibited.

! ========================================
! Logging Configuration
! ========================================
logging enable
logging timestamp
logging trap informational
logging buffered informational
logging console critical
logging host inside 172.20.242.30 udp/514

! ========================================
! NTP Configuration
! ========================================
ntp server 172.16.101.1 prefer
ntp authenticate
ntp authentication-key 1 md5 ChangeThisNTPKey123
ntp trusted-key 1

! ========================================
! SSH Configuration
! ========================================
crypto key generate rsa modulus 2048
ssh version 2
ssh timeout 15
ssh key-exchange group dh-group14-sha1

! ========================================
! Service Hardening
! ========================================
no service password-recovery
no http server enable
service password-encryption

! ========================================
! Timeout Configuration
! ========================================
timeout uauth 0:15:00 absolute
timeout conn 1:00:00

! ========================================
! IP Verification
! ========================================
! Note: Apply to specific interfaces as needed

! ========================================
! SSL/TLS Configuration
! ========================================
ssl server-version tlsv1.2
ssl cipher tlsv1.2 custom "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384"

! ========================================
! SNMP Configuration (SNMPv3 only)
! ========================================
! Configure SNMPv3 user
snmp-server group STIG-GROUP v3 priv
snmp-server user snmp-admin STIG-GROUP v3 auth sha AuthPassword123 priv aes 256 PrivPassword123

! ========================================
! Save Configuration
! ========================================
exit
write memory
"@

if ($DryRun) {
    Write-Log "DRY RUN MODE - Commands that would be executed:" "WARN"
    $ciscoCommands -split "`n" | ForEach-Object {
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
        Write-Log "Connected to device" "SUCCESS"
        
        # Send commands
        $commandList = $ciscoCommands -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*!' }
        
        foreach ($command in $commandList) {
            $command = $command.Trim()
            if ([string]::IsNullOrWhiteSpace($command)) { continue }
            
            Write-Log "Executing: $command" "INFO"
            $Stream.WriteLine($command)
            Start-Sleep -Milliseconds 500
            
            # Read output
            $output = $Stream.Read()
            if ($output -match "error|invalid|failed") {
                Write-Log "Command may have failed: $command" "WARN"
                Write-Log "Output: $output" "WARN"
            }
        }
        
        # Final read to capture any remaining output
        Start-Sleep -Seconds 2
        $finalOutput = $Stream.Read()
        Write-Log "Final output: $finalOutput" "INFO"
        
        Write-Log "All commands sent successfully" "SUCCESS"
        
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
Write-Log "Cisco FTD STIG Deployment Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log ""
Write-Log "IMPORTANT NEXT STEPS:" "WARN"
Write-Log "1. Verify configuration: show running-config" "WARN"
Write-Log "2. Test SSH access with new settings" "WARN"
Write-Log "3. Verify NTP synchronization: show ntp status" "WARN"
Write-Log "4. Check logging: show logging" "WARN"
Write-Log "5. Configure interface-specific settings (ACLs, inspection)" "WARN"
Write-Log "6. Update NTP key and SNMP passwords with secure values" "WARN"
Write-Log "7. Save configuration to startup-config if not auto-saved" "WARN"
Write-Log "8. Backup configuration to TFTP/SCP server" "WARN"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
