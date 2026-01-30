# PowerShell Script to Apply Windows Server 2019 STIG
# Based on: U_MS_Windows_Server_2019_V3R7_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: Run as Administrator
# .\Apply-Server2019-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\Server2019-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\Logs\STIG-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
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

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created registry path: $Path" "INFO"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "Set $Path\$Name = $Value" "SUCCESS"
    }
    catch {
        Write-Log "Failed to set $Path\$Name : $_" "ERROR"
    }
}

function Backup-SecuritySettings {
    Write-Log "Creating backup of current settings..." "INFO"
    
    # Create backup directory
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    
    # Export registry keys
    $regKeys = @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKLM\SOFTWARE\Policies",
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    )
    
    foreach ($key in $regKeys) {
        $fileName = $key.Replace('\', '_').Replace(':', '') + ".reg"
        reg export $key "$BackupDir\$fileName" /y | Out-Null
    }
    
    # Backup security policy
    secedit /export /cfg "$BackupDir\secedit-backup.inf" /areas SECURITYPOLICY | Out-Null
    
    # Backup audit policy
    auditpol /backup /file:"$BackupDir\auditpol-backup.csv" | Out-Null
    
    Write-Log "Backup completed: $BackupDir" "SUCCESS"
}

Write-Log "========================================"
Write-Log "Windows Server 2019 STIG Application Starting"
Write-Log "========================================"

# Create backup
Backup-SecuritySettings

Write-Log "Applying STIG configurations..." "INFO"

# ========================================
# CATEGORY I - HIGH SEVERITY
# ========================================

Write-Log "Applying Category I (High) Settings..." "INFO"

# WN19-00-000010: Systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode
Write-Log "NOTE: UEFI mode must be verified in BIOS settings" "WARN"

# WN19-00-000020: Secure Boot must be enabled
Write-Log "NOTE: Secure Boot must be enabled in UEFI firmware" "WARN"

# WN19-00-000030: Windows Server 2019 must be activated
# Manual check required

# WN19-00-000040: Local volumes must use NTFS
Write-Log "NOTE: Verify all volumes are NTFS formatted" "WARN"

# WN19-00-000050: Alternate operating systems must not be permitted on the same system
Write-Log "NOTE: Ensure no dual-boot configuration exists" "WARN"

# WN19-00-000060: Windows Server 2019 must be a domain member
Write-Log "NOTE: System should be domain-joined" "WARN"

# WN19-00-000070: Unused accounts must be disabled or removed
Write-Log "NOTE: Review and disable unused accounts manually" "WARN"

# WN19-AU-000010 through WN19-AU-000100: Advanced Audit Policy
Write-Log "Configuring Advanced Audit Policies..." "INFO"

# Force audit policy subcategory settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

# Credential Validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Application Group Management
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable

# Security Group Management
auditpol /set /subcategory:"Security Group Management" /success:enable

# User Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Plug and Play Events
auditpol /set /subcategory:"Plug and Play Events" /success:enable

# Process Creation
auditpol /set /subcategory:"Process Creation" /success:enable

# Account Lockout
auditpol /set /subcategory:"Account Lockout" /failure:enable

# Group Membership
auditpol /set /subcategory:"Group Membership" /success:enable

# Logoff
auditpol /set /subcategory:"Logoff" /success:enable

# Logon
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Special Logon
auditpol /set /subcategory:"Special Logon" /success:enable

# File Share
auditpol /set /subcategory:"File Share" /success:enable /failure:enable

# Other Object Access Events
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Removable Storage
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Audit Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable

# Authentication Policy Change
auditpol /set /subcategory:"Authentication Policy Change" /success:enable

# Authorization Policy Change
auditpol /set /subcategory:"Authorization Policy Change" /success:enable

# Sensitive Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# IPsec Driver
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

# Security State Change
auditpol /set /subcategory:"Security State Change" /success:enable

# Security System Extension
auditpol /set /subcategory:"Security System Extension" /success:enable

# System Integrity
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

Write-Log "Advanced Audit Policies configured" "SUCCESS"

# ========================================
# CATEGORY II - MEDIUM SEVERITY
# ========================================

Write-Log "Applying Category II (Medium) Settings..." "INFO"

# WN19-CC-000010: Account lockout duration
# Configured via secedit below

# WN19-CC-000020: Account lockout threshold
# Configured via secedit below

# WN19-CC-000030: Reset account lockout counter
# Configured via secedit below

# Configure Account Policies via secedit
$secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 3
ResetLockoutCount = 15
LockoutDuration = 15
[Event Audit]
[Registry Values]
[Privilege Rights]
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

$secpolFile = "$env:TEMP\secpol-stig.inf"
$secpolContent | Out-File $secpolFile -Encoding Unicode

secedit /configure /db secedit.sdb /cfg $secpolFile /areas SECURITYPOLICY | Out-Null
Remove-Item $secpolFile -Force

Write-Log "Account policies configured" "SUCCESS"

# WN19-CC-000040: Reversible encryption
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1

# WN19-CC-000050: Anonymous SID/Name translation
# Handled by LSA policy (requires domain configuration)

# WN19-CC-000060: Anonymous enumeration of SAM accounts
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# WN19-CC-000070: Anonymous enumeration of shares
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# WN19-CC-000080: Anonymous access to Named Pipes and Shares
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# WN19-CC-000090: Remotely accessible registry paths
$regPaths = @("System\CurrentControlSet\Control\ProductOptions", "System\CurrentControlSet\Control\Server Applications", "Software\Microsoft\Windows NT\CurrentVersion")
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value $regPaths -Type MultiString

# WN19-CC-000100: Remotely accessible registry paths and sub-paths
$regSubPaths = @("Software\Microsoft\OLAP Server", "Software\Microsoft\Windows NT\CurrentVersion\Print", "Software\Microsoft\Windows NT\CurrentVersion\Windows", "System\CurrentControlSet\Control\ContentIndex", "System\CurrentControlSet\Control\Print\Printers", "System\CurrentControlSet\Control\Terminal Server", "System\CurrentControlSet\Control\Terminal Server\UserConfig", "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", "System\CurrentControlSet\Services\Eventlog", "System\CurrentControlSet\Services\Sysmonlog")
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value $regSubPaths -Type MultiString

# WN19-CC-000110: LAN Manager authentication level
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# WN19-CC-000120: LAN Manager hash storage
# Already configured above with NoLMHash

# WN19-CC-000130: LDAP client signing
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2

# WN19-CC-000140: NetBIOS name release attacks
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1

# WN19-CC-000150: Outgoing secure channel traffic encryption
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1

# WN19-CC-000160: Session security for NTLM SSP based clients
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 0x20080000

# WN19-CC-000170: Session security for NTLM SSP based servers
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 0x20080000

# WN19-DC-000010 through WN19-DC-000090: Domain Controller specific settings
Write-Log "NOTE: Domain Controller specific settings require manual configuration" "WARN"

# WN19-SO-000010: Access Credential Manager as a trusted caller
# Configured via Group Policy - should be "No One"

# WN19-SO-000020: Access this computer from the network
# Configured via Group Policy

# WN19-SO-000030: Act as part of the operating system
# Configured via Group Policy - should be "No One"

# WN19-SO-000040: Add workstations to domain
# Domain Controller only

# WN19-SO-000050: Adjust memory quotas for a process
# Configured via Group Policy

# WN19-SO-000060: Allow log on locally
# Configured via Group Policy

# WN19-SO-000070: Allow log on through Remote Desktop Services
# Configured via Group Policy

# WN19-SO-000080: Back up files and directories
# Configured via Group Policy

# WN19-SO-000090: Change the system time
# Configured via Group Policy

# WN19-SO-000100: Change the time zone
# Configured via Group Policy

# WN19-SO-000110: Create a pagefile
# Configured via Group Policy

# WN19-SO-000120: Create a token object
# Configured via Group Policy - should be "No One"

# WN19-SO-000130: Create global objects
# Configured via Group Policy

# WN19-SO-000140: Create permanent shared objects
# Configured via Group Policy - should be "No One"

# WN19-SO-000150: Create symbolic links
# Configured via Group Policy

# WN19-SO-000160: Debug programs
# Configured via Group Policy - Administrators only

# WN19-SO-000170: Deny access to this computer from the network
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# WN19-SO-000180: Deny log on as a batch job
# Configured via Group Policy

# WN19-SO-000190: Deny log on as a service
# Configured via Group Policy

# WN19-SO-000200: Deny log on locally
# Configured via Group Policy

# WN19-SO-000210: Deny log on through Remote Desktop Services
# Configured via Group Policy

# WN19-SO-000220: Enable computer and user accounts to be trusted for delegation
# Configured via Group Policy - should be "No One" (unless specific need)

# WN19-SO-000230: Force shutdown from a remote system
# Configured via Group Policy

# WN19-SO-000240: Generate security audits
# Configured via Group Policy

# WN19-SO-000250: Impersonate a client after authentication
# Configured via Group Policy

# WN19-SO-000260: Increase scheduling priority
# Configured via Group Policy

# WN19-SO-000270: Load and unload device drivers
# Configured via Group Policy

# WN19-SO-000280: Lock pages in memory
# Configured via Group Policy - should be "No One"

# WN19-SO-000290: Manage auditing and security log
# Configured via Group Policy

# WN19-SO-000300: Modify an object label
# Configured via Group Policy - should be "No One"

# WN19-SO-000310: Modify firmware environment values
# Configured via Group Policy

# WN19-SO-000320: Perform volume maintenance tasks
# Configured via Group Policy

# WN19-SO-000330: Profile single process
# Configured via Group Policy

# WN19-SO-000340: Profile system performance
# Configured via Group Policy

# WN19-SO-000350: Replace a process level token
# Configured via Group Policy

# WN19-SO-000360: Restore files and directories
# Configured via Group Policy

# WN19-SO-000370: Shut down the system
# Configured via Group Policy

# WN19-SO-000380: Take ownership of files or other objects
# Configured via Group Policy

# Account and Authentication Policies
Write-Log "Configuring additional security options..." "INFO"

# WN19-SO-000390: Anonymous access to registry
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# WN19-SO-000400: Audit account management events
# Already configured in audit policy section

# SMB Security
Write-Log "Configuring SMB security..." "INFO"

# WN19-SO-000410: SMB Server signing
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# WN19-SO-000420: SMB Client signing
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# WN19-SO-000430: SMB v1 must be disabled
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -WarningAction SilentlyContinue

# Network Security
Write-Log "Configuring network security..." "INFO"

# WN19-SO-000440: IPv6 source routing
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2

# WN19-SO-000450: IPv4 source routing
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2

# WN19-SO-000460: ICMP redirects
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0

# WN19-SO-000470: NetBIOS name release protection
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1

# WN19-SO-000480: Ignore NetBIOS name release requests except from WINS servers
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NodeType" -Value 8

# Remote Desktop Services (RDS) Security
Write-Log "Configuring Remote Desktop Services security..." "INFO"

# WN19-CC-000330: RDS encryption level
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3

# WN19-CC-000340: Require NLA
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2

# WN19-CC-000350: RDS must delete temporary folders on exit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value 1

# WN19-CC-000360: RDS must not allow passwords to be saved
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1

# Windows Defender
Write-Log "Configuring Windows Defender..." "INFO"

# WN19-EP-000010: Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

# WN19-EP-000020: Windows Defender behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue

# WN19-EP-000030: Windows Defender scanning of scripts
Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue

# WN19-EP-000040: Windows Defender email scanning
Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue

# PowerShell Logging
Write-Log "Configuring PowerShell logging..." "INFO"

# WN19-CC-000390: PowerShell script block logging
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# WN19-CC-000400: PowerShell transcription
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell" -Type String
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1

# Create PowerShell log directory
New-Item -Path "C:\Windows\Logs\PowerShell" -ItemType Directory -Force | Out-Null

# WN19-CC-000410: PowerShell module logging
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Windows Firewall
Write-Log "Configuring Windows Firewall..." "INFO"

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# WN19-CC-000420: Firewall logging
Set-NetFirewallProfile -Profile Domain -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384

# Event Log Configuration
Write-Log "Configuring event logs..." "INFO"

# WN19-CC-000430: Application event log size
wevtutil sl Application /ms:32768000

# WN19-CC-000440: Security event log size
wevtutil sl Security /ms:1024000000

# WN19-CC-000450: System event log size
wevtutil sl System /ms:32768000

# Configure event log retention
wevtutil sl Application /rt:false /ab:true
wevtutil sl Security /rt:false /ab:true
wevtutil sl System /rt:false /ab:true

# Additional Services Configuration
Write-Log "Configuring services..." "INFO"

# WN19-CC-000460: Disable RemoteRegistry service
Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# WN19-CC-000470: Disable Simple TCP/IP Services
Set-Service -Name simptcp -StartupType Disabled -ErrorAction SilentlyContinue

# WN19-CC-000480: Disable FTPSVC if not needed for FTP server role
# Set-Service -Name FTPSVC -StartupType Disabled -ErrorAction SilentlyContinue

# Credential Guard and Device Guard
Write-Log "NOTE: Credential Guard requires hardware support (TPM 2.0, UEFI, VBS)" "WARN"
Write-Log "NOTE: Enable Credential Guard via Group Policy if hardware supports it" "WARN"

# BitLocker (if applicable)
Write-Log "NOTE: Configure BitLocker manually for data protection" "WARN"

# ========================================
# CATEGORY III - LOW SEVERITY
# ========================================

Write-Log "Applying Category III (Low) Settings..." "INFO"

# WN19-CC-000500: Autoplay must be disabled for all drives
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# WN19-CC-000510: Autoplay must be disabled for non-volume devices
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1

# WN19-CC-000520: Enhanced anti-spoofing for facial recognition
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1

# WN19-CC-000530: Solicited Remote Assistance
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0

# WN19-CC-000540: Unsolicited Remote Assistance
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0

# WN19-CC-000550: Internet Connection Sharing
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0

Write-Log "Category III settings applied" "SUCCESS"

Write-Log ""
Write-Log "========================================"
Write-Log "Windows Server 2019 STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Backup directory: $BackupDir"
Write-Log ""
Write-Log "=== IMPORTANT NEXT STEPS ===" "WARN"
Write-Log "1. Reboot the system to apply all settings"
Write-Log "2. Verify UEFI and Secure Boot are enabled in firmware"
Write-Log "3. Ensure system is domain-joined for full STIG compliance"
Write-Log "4. Configure User Rights Assignments via Group Policy"
Write-Log "5. Enable Credential Guard if hardware supports it"
Write-Log "6. Configure BitLocker for system and data drives"
Write-Log "7. Review and configure user accounts and permissions"
Write-Log "8. Test Remote Desktop access with NLA requirement"
Write-Log "9. Configure network firewall rules as needed"
Write-Log "10. Run SCAP scan for compliance validation"
Write-Log ""
Write-Log "To restore from backup if needed:"
Write-Log "  Registry: Use .reg files in $BackupDir"
Write-Log "  Security Policy: secedit /configure /db secedit.sdb /cfg $BackupDir\secedit-backup.inf"
Write-Log "  Audit Policy: auditpol /restore /file:$BackupDir\auditpol-backup.csv"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
