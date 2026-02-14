<#
.SYNOPSIS
    Windows 11 24H2 STIG Implementation Script
.DESCRIPTION
    Applies STIG security controls for Windows 11 Enterprise 24H2 based on
    U_MS_Windows_11_V2R6_Manual_STIG
.NOTES
    Version: 1.0
    Date: January 30, 2026
    Run as Administrator
    This script implements automated STIG controls.
    Manual verification and domain GPO application may still be required.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$CreateBackup = $true
)

$ErrorActionPreference = 'Continue'
$script:LogFile = "C:\Windows\Logs\STIG-Application-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logMessage
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created registry path: $Path" "INFO"
        }
        
        if ($WhatIf) {
            Write-Log "[WHATIF] Would set $Path\$Name = $Value ($Type)" "INFO"
            return
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "SUCCESS: $Description" "SUCCESS"
        Write-Log "  Set $Path\$Name = $Value" "INFO"
    }
    catch {
        Write-Log "ERROR setting $Path\$Name : $_" "ERROR"
    }
}

function Backup-SecuritySettings {
    if ($CreateBackup -and !$WhatIf) {
        $backupDir = "C:\Windows\STIG-Backups\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        
        Write-Log "Creating backup in $backupDir" "INFO"
        
        # Export registry settings
        reg export "HKLM\SOFTWARE\Policies" "$backupDir\Policies.reg" /y | Out-Null
        reg export "HKLM\SYSTEM\CurrentControlSet\Control" "$backupDir\Control.reg" /y | Out-Null
        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" "$backupDir\WindowsPolicies.reg" /y | Out-Null
        
        # Export security policy
        secedit /export /cfg "$backupDir\SecPol.inf" /quiet
        
        # Export audit policy
        auditpol /backup /file:"$backupDir\AuditPol.csv"
        
        Write-Log "Backup completed: $backupDir" "SUCCESS"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Windows 11 STIG Application Starting" "INFO"
Write-Log "========================================" "INFO"

if ($WhatIf) {
    Write-Log "Running in WHATIF mode - no changes will be made" "WARN"
}

# Create backup before making changes
Backup-SecuritySettings

Write-Log "`n=== Account Policies ===" "INFO"

# Account Lockout Policy
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" `
    -Name "MaxDenials" -Value 3 -Type DWord `
    -Description "WN11-AC-000005: Account lockout threshold to 3 attempts"

# Password Policy (via secpol)
if (!$WhatIf) {
    try {
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
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secpolContent | Out-File -FilePath $tempFile -Encoding unicode
        secedit /configure /db secedit.sdb /cfg $tempFile /quiet
        Remove-Item $tempFile
        Write-Log "SUCCESS: Applied password and account lockout policies" "SUCCESS"
    }
    catch {
        Write-Log "ERROR applying security policies: $_" "ERROR"
    }
}

Write-Log "`n=== Audit Policies ===" "INFO"

# Configure Advanced Audit Policies
$auditPolicies = @(
    @{Category = "Account Logon"; Subcategory = "Credential Validation"; Setting = "Success,Failure"}
    @{Category = "Account Management"; Subcategory = "Security Group Management"; Setting = "Success"}
    @{Category = "Account Management"; Subcategory = "User Account Management"; Setting = "Success,Failure"}
    @{Category = "Detailed Tracking"; Subcategory = "Process Creation"; Setting = "Success"}
    @{Category = "Logon/Logoff"; Subcategory = "Logoff"; Setting = "Success"}
    @{Category = "Logon/Logoff"; Subcategory = "Logon"; Setting = "Success,Failure"}
    @{Category = "Logon/Logoff"; Subcategory = "Special Logon"; Setting = "Success"}
    @{Category = "Policy Change"; Subcategory = "Audit Policy Change"; Setting = "Success"}
    @{Category = "Policy Change"; Subcategory = "Authentication Policy Change"; Setting = "Success"}
    @{Category = "Privilege Use"; Subcategory = "Sensitive Privilege Use"; Setting = "Success,Failure"}
    @{Category = "System"; Subcategory = "Security State Change"; Setting = "Success"}
    @{Category = "System"; Subcategory = "Security System Extension"; Setting = "Success"}
    @{Category = "System"; Subcategory = "System Integrity"; Setting = "Success,Failure"}
)

foreach ($policy in $auditPolicies) {
    if (!$WhatIf) {
        try {
            auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>$null
            Write-Log "Set audit policy: $($policy.Subcategory) = $($policy.Setting)" "SUCCESS"
        }
        catch {
            Write-Log "ERROR setting audit policy $($policy.Subcategory): $_" "ERROR"
        }
    }
    else {
        Write-Log "[WHATIF] Would set audit policy: $($policy.Subcategory) = $($policy.Setting)" "INFO"
    }
}

Write-Log "`n=== Security Options ===" "INFO"

# Force audit policy subcategory settings
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord `
    -Description "Force audit policy subcategory settings"

# Interactive Logon - Legal Notice
$legalNoticeText = @"
This is a CCDC computer, please dont try to hack it. That would be rude.
"@

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText" -Value $legalNoticeText -Type String `
    -Description "WN11-SO-000075: Legal notice text"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Value "DoD Notice and Consent Banner" -Type String `
    -Description "WN11-SO-000080: Legal notice caption"

# Machine Inactivity Limit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Value 900 -Type DWord `
    -Description "WN11-SO-000085: Machine inactivity limit - 15 minutes"

# User Account Control Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1 -Type DWord `
    -Description "WN11-SO-000215: Enable User Account Control"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord `
    -Description "WN11-SO-000220: UAC - Prompt for consent for administrators"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord `
    -Description "WN11-SO-000225: UAC - Auto deny elevation requests for standard users"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableInstallerDetection" -Value 1 -Type DWord `
    -Description "WN11-SO-000235: UAC - Detect application installations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableSecureUIAPaths" -Value 1 -Type DWord `
    -Description "WN11-SO-000245: UAC - Only elevate UIAccess applications in secure locations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableVirtualization" -Value 1 -Type DWord `
    -Description "WN11-SO-000250: UAC - Virtualize file and registry write failures"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "FilterAdministratorToken" -Value 1 -Type DWord `
    -Description "WN11-SO-000255: UAC - Admin Approval Mode for built-in Administrator"

Write-Log "`n=== LSA Settings ===" "INFO"

# LSA Protection
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord `
    -Description "WN11-CC-000065: LSA Protection enabled"

# LSASS Audit Mode
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" `
    -Name "AuditLevel" -Value 8 -Type DWord `
    -Description "WN11-CC-000070: LSASS.exe Audit Mode"

# Disable LM Hash
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "NoLMHash" -Value 1 -Type DWord `
    -Description "WN11-SO-000145: LAN Manager hash disabled"

# Disable storage of passwords and credentials
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "DisableDomainCreds" -Value 1 -Type DWord `
    -Description "WN11-SO-000110: Disable storage of passwords"

# LAN Manager Authentication Level
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord `
    -Description "WN11-SO-000150: LAN Manager authentication - NTLMv2 only"

Write-Log "`n=== Network Security ===" "INFO"

# SMB Settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" -Value 0 -Type DWord `
    -Description "WN11-CC-000315: Disable SMB1"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN11-SO-000185: SMB Server - Require security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN11-SO-000195: SMB Client - Require security signature"

# Disable IPv6
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
    -Name "DisabledComponents" -Value 255 -Type DWord `
    -Description "WN11-CC-000200: Disable IPv6 (if not used)"

# Windows Remote Management
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN11-CC-000325: WinRM Client - Disallow Basic authentication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN11-CC-000330: WinRM Client - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowDigest" -Value 0 -Type DWord `
    -Description "WN11-CC-000335: WinRM Client - Disallow Digest authentication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN11-CC-000340: WinRM Service - Disallow Basic authentication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN11-CC-000350: WinRM Service - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "DisableRunAs" -Value 1 -Type DWord `
    -Description "WN11-CC-000355: WinRM Service - Disallow RunAs"

Write-Log "`n=== Windows Defender ===" "INFO"

# Windows Defender Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Value 0 -Type DWord `
    -Description "WN11-CC-000005: Windows Defender AntiVirus enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord `
    -Description "WN11-CC-000010: Windows Defender Real-time protection enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord `
    -Description "WN11-CC-000015: Windows Defender Behavior monitoring enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
    -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -Type DWord `
    -Description "WN11-CC-000020: Windows Defender - Check for signature updates before scanning"

# Windows Defender Exploit Guard
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
    -Name "EnableNetworkProtection" -Value 1 -Type DWord `
    -Description "WN11-CC-000025: Windows Defender Exploit Guard Network Protection enabled"

# Windows Defender Application Guard
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" `
    -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord `
    -Description "WN11-CC-000030: Windows Defender Application Guard enabled (Enterprise mode)"

Write-Log "`n=== Credential Guard & Device Guard ===" "INFO"

# Virtualization Based Security
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord `
    -Description "WN11-CC-000075: Enable Virtualization Based Security"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord `
    -Description "WN11-CC-000080: Require Secure Boot and DMA Protection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "LsaCfgFlags" -Value 1 -Type DWord `
    -Description "WN11-CC-000090: Enable Credential Guard"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "ConfigureSystemGuardLaunch" -Value 1 -Type DWord `
    -Description "WN11-CC-000095: Enable System Guard Secure Launch"

Write-Log "`n=== BitLocker Settings ===" "INFO"

# BitLocker Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseAdvancedStartup" -Value 1 -Type DWord `
    -Description "WN11-CC-000100: BitLocker - Require additional authentication at startup"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPMPIN" -Value 1 -Type DWord `
    -Description "WN11-CC-000105: BitLocker - Require startup PIN with TPM"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "MinimumPIN" -Value 6 -Type DWord `
    -Description "WN11-CC-000110: BitLocker - Minimum PIN length of 6"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPM" -Value 2 -Type DWord `
    -Description "WN11-CC-000115: BitLocker - Do not allow TPM without additional authentication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "EnableBDEWithNoTPM" -Value 0 -Type DWord `
    -Description "WN11-CC-000120: BitLocker - Require TPM"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPMKey" -Value 2 -Type DWord `
    -Description "WN11-CC-000125: BitLocker - Do not allow TPM startup key"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPMKeyPIN" -Value 1 -Type DWord `
    -Description "WN11-CC-000130: BitLocker - Allow TPM startup key and PIN"

# BitLocker Recovery
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "FDVRecoveryPassword" -Value 2 -Type DWord `
    -Description "WN11-CC-000135: BitLocker - Require recovery password for fixed drives"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "FDVRecoveryKey" -Value 2 -Type DWord `
    -Description "WN11-CC-000140: BitLocker - Allow recovery key for fixed drives"

Write-Log "`n=== Remote Desktop Services ===" "INFO"

# Remote Desktop Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic" -Value 1 -Type DWord `
    -Description "WN11-CC-000145: RDS - Require secure RPC communication"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel" -Value 3 -Type DWord `
    -Description "WN11-CC-000150: RDS - Set client connection encryption to High"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword" -Value 1 -Type DWord `
    -Description "WN11-CC-000155: RDS - Always prompt for password"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fDisableCdm" -Value 1 -Type DWord `
    -Description "WN11-CC-000160: RDS - Disable drive redirection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "SecurityLayer" -Value 2 -Type DWord `
    -Description "WN11-CC-000165: RDS - Require use of specific security layer (SSL/TLS)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "UserAuthentication" -Value 1 -Type DWord `
    -Description "WN11-CC-000170: RDS - Require Network Level Authentication"

Write-Log "`n=== PowerShell Settings ===" "INFO"

# PowerShell Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord `
    -Description "WN11-CC-000175: PowerShell - Enable Script Block Logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord `
    -Description "WN11-CC-000180: PowerShell - Enable Script Block Invocation Logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord `
    -Description "WN11-CC-000185: PowerShell - Enable Module Logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -Value 1 -Type DWord `
    -Description "WN11-CC-000190: PowerShell - Enable Transcription"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell\Transcripts" -Type String `
    -Description "WN11-CC-000195: PowerShell - Transcription output directory"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableInvocationHeader" -Value 1 -Type DWord `
    -Description "WN11-CC-000200: PowerShell - Include invocation headers in transcripts"

Write-Log "`n=== Windows Firewall ===" "INFO"

# Windows Firewall Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN11-CC-000205: Windows Firewall - Domain Profile enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "DefaultOutboundAction" -Value 0 -Type DWord `
    -Description "WN11-CC-000210: Windows Firewall - Domain Profile default outbound = Allow"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "DefaultInboundAction" -Value 1 -Type DWord `
    -Description "WN11-CC-000215: Windows Firewall - Domain Profile default inbound = Block"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFilePath" -Value "C:\Windows\System32\logfiles\firewall\domainfw.log" -Type String `
    -Description "WN11-CC-000220: Windows Firewall - Domain Profile log file path"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFileSize" -Value 16384 -Type DWord `
    -Description "WN11-CC-000225: Windows Firewall - Domain Profile log file size"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN11-CC-000230: Windows Firewall - Private Profile enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN11-CC-000235: Windows Firewall - Public Profile enabled"

Write-Log "`n=== Event Log Settings ===" "INFO"

# Event Log Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
    -Name "MaxSize" -Value 32768 -Type DWord `
    -Description "WN11-CC-000240: Application Event Log - Minimum 32 MB"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -Name "MaxSize" -Value 1024000 -Type DWord `
    -Description "WN11-CC-000245: Security Event Log - Minimum 1 GB"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
    -Name "MaxSize" -Value 32768 -Type DWord `
    -Description "WN11-CC-000250: System Event Log - Minimum 32 MB"

# Include command line in process creation events
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord `
    -Description "WN11-CC-000255: Include command line in process creation events"

Write-Log "`n=== Application Control ===" "INFO"

# Windows Store
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" `
    -Name "RemoveWindowsStore" -Value 1 -Type DWord `
    -Description "WN11-CC-000260: Disable Windows Store (if not needed)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" `
    -Name "DisableStoreApps" -Value 1 -Type DWord `
    -Description "WN11-CC-000265: Disable Windows Store apps (if not needed)"

# AutoPlay
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoAutorun" -Value 1 -Type DWord `
    -Description "WN11-CC-000270: Disable AutoRun"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord `
    -Description "WN11-CC-000275: Disable AutoPlay for non-volume devices"

# Camera
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" `
    -Name "AllowCamera" -Value 0 -Type DWord `
    -Description "WN11-CC-000280: Disable Camera (if not needed)"

Write-Log "`n=== Network Settings ===" "INFO"

# Network Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN11-CC-000285: Hardened UNC Paths - NETLOGON"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN11-CC-000290: Hardened UNC Paths - SYSVOL"

# DNS Client
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord `
    -Description "WN11-CC-000295: Disable Multicast Name Resolution"

# LLMNR
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableLLMNR" -Value 0 -Type DWord `
    -Description "WN11-CC-000300: Disable LLMNR"

# WPAD
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" `
    -Name "WpadOverride" -Value 1 -Type DWord `
    -Description "WN11-CC-000305: Disable WPAD"

Write-Log "`n=== Privacy Settings ===" "INFO"

# Privacy Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowTelemetry" -Value 0 -Type DWord `
    -Description "WN11-CC-000310: Disable Telemetry (Security level)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsAccessAccountInfo" -Value 2 -Type DWord `
    -Description "WN11-CC-000315: Prevent apps from accessing account information"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsAccessLocation" -Value 2 -Type DWord `
    -Description "WN11-CC-000320: Prevent apps from accessing location"

# Cortana
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
    -Name "AllowCortana" -Value 0 -Type DWord `
    -Description "WN11-CC-000325: Disable Cortana"

Write-Log "`n=== Internet Explorer/Edge Settings ===" "INFO"

# Internet Explorer
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" `
    -Name "DisableFirstRunCustomize" -Value 1 -Type DWord `
    -Description "WN11-CC-000330: IE - Disable First Run Customize"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" `
    -Name "PreventFirstRunPage" -Value 1 -Type DWord `
    -Description "WN11-CC-000335: Edge - Prevent First Run Page"

# Edge SmartScreen
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" `
    -Name "EnabledV9" -Value 1 -Type DWord `
    -Description "WN11-CC-000340: Edge - Enable SmartScreen Filter"

Write-Log "`n=== Additional Hardening ===" "INFO"

# Disable Guest Account
if (!$WhatIf) {
    try {
        net user Guest /active:no 2>$null
        Write-Log "SUCCESS: Guest account disabled" "SUCCESS"
    }
    catch {
        Write-Log "ERROR disabling Guest account: $_" "ERROR"
    }
}

# Disable unnecessary services
$servicesToDisable = @(
    "RemoteRegistry",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "XboxGipSvc"
)

foreach ($service in $servicesToDisable) {
    if (!$WhatIf) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "SUCCESS: Disabled service: $service" "SUCCESS"
            }
        }
        catch {
            Write-Log "WARNING: Could not disable service $service : $_" "WARN"
        }
    }
    else {
        Write-Log "[WHATIF] Would disable service: $service" "INFO"
    }
}

# Configure Windows Update
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" -Value 0 -Type DWord `
    -Description "WN11-CC-000345: Enable Automatic Updates"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "AUOptions" -Value 4 -Type DWord `
    -Description "WN11-CC-000350: Auto download and schedule install"

Write-Log "`n========================================" "INFO"
Write-Log "Windows 11 STIG Application Completed" "SUCCESS"
Write-Log "========================================" "INFO"
Write-Log "`nLog file: $script:LogFile" "INFO"
Write-Log "`nIMPORTANT: A system restart is required for all changes to take effect." "WARN"
Write-Log "IMPORTANT: Review the log file for any errors or warnings." "WARN"
Write-Log "IMPORTANT: Some settings require Group Policy or manual configuration." "WARN"

# Summary
Write-Log "`n=== NEXT STEPS ===" "INFO"
Write-Log "1. Restart the system to apply all changes" "INFO"
Write-Log "2. Verify BitLocker is enabled and configured" "INFO"
Write-Log "3. Verify Credential Guard is enabled: Get-ComputerInfo | Select-Object DeviceGuardSmartStatus" "INFO"
Write-Log "4. Run SCC/SCAP scan to verify compliance" "INFO"
Write-Log "5. Review and apply domain-level Group Policies" "INFO"
Write-Log "6. Verify TPM is enabled and functioning" "INFO"
Write-Log "7. Verify Secure Boot is enabled" "INFO"
