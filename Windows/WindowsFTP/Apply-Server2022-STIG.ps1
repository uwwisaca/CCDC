<#
.SYNOPSIS
    Windows Server 2022 STIG Implementation Script
.DESCRIPTION
    Applies STIG security controls for Windows Server 2022 Standard based on
    U_MS_Windows_Server_2022_V2R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: January 30, 2026
    Run as Administrator
    For FTP Server role - includes base OS and web server hardening
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$CreateBackup = $true
)

$ErrorActionPreference = 'Continue'
$script:LogFile = "C:\Windows\Logs\STIG-Application-Server2022-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
        }
        
        if ($WhatIf) {
            Write-Log "[WHATIF] Would set $Path\$Name = $Value ($Type)" "INFO"
            return
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "SUCCESS: $Description" "SUCCESS"
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
        
        reg export "HKLM\SOFTWARE\Policies" "$backupDir\Policies.reg" /y | Out-Null
        reg export "HKLM\SYSTEM\CurrentControlSet\Control" "$backupDir\Control.reg" /y | Out-Null
        secedit /export /cfg "$backupDir\SecPol.inf" /quiet
        auditpol /backup /file:"$backupDir\AuditPol.csv"
        
        Write-Log "Backup completed: $backupDir" "SUCCESS"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Windows Server 2022 STIG Application Starting" "INFO"
Write-Log "========================================" "INFO"

Backup-SecuritySettings

Write-Log "`n=== Account Policies ===" "INFO"

# Account Lockout and Password Policies
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

# Advanced Audit Policies
$auditPolicies = @(
    @{Subcategory = "Credential Validation"; Setting = "Success,Failure"}
    @{Subcategory = "Security Group Management"; Setting = "Success"}
    @{Subcategory = "User Account Management"; Setting = "Success,Failure"}
    @{Subcategory = "Computer Account Management"; Setting = "Success"}
    @{Subcategory = "Other Account Management Events"; Setting = "Success,Failure"}
    @{Subcategory = "Process Creation"; Setting = "Success"}
    @{Subcategory = "Process Termination"; Setting = "Success"}
    @{Subcategory = "Account Lockout"; Setting = "Failure"}
    @{Subcategory = "Logoff"; Setting = "Success"}
    @{Subcategory = "Logon"; Setting = "Success,Failure"}
    @{Subcategory = "Special Logon"; Setting = "Success"}
    @{Subcategory = "Audit Policy Change"; Setting = "Success"}
    @{Subcategory = "Authentication Policy Change"; Setting = "Success"}
    @{Subcategory = "Authorization Policy Change"; Setting = "Success"}
    @{Subcategory = "Sensitive Privilege Use"; Setting = "Success,Failure"}
    @{Subcategory = "IPsec Driver"; Setting = "Success,Failure"}
    @{Subcategory = "Security State Change"; Setting = "Success"}
    @{Subcategory = "Security System Extension"; Setting = "Success"}
    @{Subcategory = "System Integrity"; Setting = "Success,Failure"}
)

foreach ($policy in $auditPolicies) {
    if (!$WhatIf) {
        try {
            auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>$null
            Write-Log "Set audit policy: $($policy.Subcategory)" "SUCCESS"
        }
        catch {
            Write-Log "ERROR setting audit policy $($policy.Subcategory): $_" "ERROR"
        }
    }
}

Write-Log "`n=== Security Options ===" "INFO"

# Force audit policy subcategory settings
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord `
    -Description "WN22-SO-000050: Force audit policy subcategory settings"

# Legal Notice
$legalNoticeText = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
"@

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText" -Value $legalNoticeText -Type String `
    -Description "WN22-SO-000130: Legal notice text"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Value "DoD Notice and Consent Banner" -Type String `
    -Description "WN22-SO-000140: Legal notice caption"

# Machine Inactivity Limit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Value 900 -Type DWord `
    -Description "WN22-SO-000120: Machine inactivity limit"

# UAC Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1 -Type DWord `
    -Description "WN22-SO-000260: Enable UAC"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord `
    -Description "WN22-SO-000270: UAC - Prompt for consent"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableInstallerDetection" -Value 1 -Type DWord `
    -Description "WN22-SO-000280: UAC - Detect application installations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableSecureUIAPaths" -Value 1 -Type DWord `
    -Description "WN22-SO-000290: UAC - Only elevate UIAccess apps in secure locations"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableVirtualization" -Value 1 -Type DWord `
    -Description "WN22-SO-000300: UAC - Virtualize file and registry write failures"

Write-Log "`n=== LSA and Authentication ===" "INFO"

# LSA Protection
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord `
    -Description "WN22-CC-000160: LSA Protection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" `
    -Name "AuditLevel" -Value 8 -Type DWord `
    -Description "WN22-CC-000170: LSASS Audit Mode"

# Disable LM Hash
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "NoLMHash" -Value 1 -Type DWord `
    -Description "WN22-SO-000150: Disable LM Hash"

# LAN Manager Authentication Level
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord `
    -Description "WN22-SO-000190: LAN Manager authentication level"

# Disable anonymous SID/Name translation
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "TurnOffAnonymousBlock" -Value 1 -Type DWord `
    -Description "WN22-SO-000080: Disable anonymous SID/Name translation"

# Do not allow anonymous enumeration of SAM accounts
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1 -Type DWord `
    -Description "WN22-SO-000100: Restrict anonymous SAM enumeration"

# Do not allow anonymous enumeration of shares
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1 -Type DWord `
    -Description "WN22-SO-000110: Restrict anonymous share enumeration"

Write-Log "`n=== Network Security ===" "INFO"

# SMB Settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" -Value 0 -Type DWord `
    -Description "WN22-CC-000330: Disable SMB1"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000310: SMB Server - Require security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000320: SMB Client - Require security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "EnableSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000330: SMB Server - Enable security signature"

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnableSecuritySignature" -Value 1 -Type DWord `
    -Description "WN22-SO-000340: SMB Client - Enable security signature"

# Disable NetBIOS over TCP/IP
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
    -Name "NodeType" -Value 2 -Type DWord `
    -Description "WN22-CC-000340: Configure NetBIOS node type"

# Windows Remote Management
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN22-CC-000350: WinRM Client - Disallow Basic auth"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN22-CC-000360: WinRM Client - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic" -Value 0 -Type DWord `
    -Description "WN22-CC-000370: WinRM Service - Disallow Basic auth"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord `
    -Description "WN22-CC-000380: WinRM Service - Disallow unencrypted traffic"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "DisableRunAs" -Value 1 -Type DWord `
    -Description "WN22-CC-000390: WinRM Service - Disable RunAs"

# Hardened UNC Paths
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN22-CC-000400: Hardened UNC Path - NETLOGON"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
    -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -Type String `
    -Description "WN22-CC-000410: Hardened UNC Path - SYSVOL"

# DNS Client Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord `
    -Description "WN22-CC-000420: Disable Multicast Name Resolution"

# Disable LLMNR
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableLLMNR" -Value 0 -Type DWord `
    -Description "WN22-CC-000430: Disable LLMNR"

Write-Log "`n=== Windows Defender ===" "INFO"

# Windows Defender Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Value 0 -Type DWord `
    -Description "WN22-CC-000040: Windows Defender enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord `
    -Description "WN22-CC-000050: Windows Defender Real-time protection enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" `
    -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -Type DWord `
    -Description "WN22-CC-000060: Check signatures before scanning"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
    -Name "EnableNetworkProtection" -Value 1 -Type DWord `
    -Description "WN22-CC-000070: Enable Network Protection"

Write-Log "`n=== Remote Desktop Services ===" "INFO"

# RDS Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic" -Value 1 -Type DWord `
    -Description "WN22-CC-000440: RDS - Require secure RPC"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel" -Value 3 -Type DWord `
    -Description "WN22-CC-000450: RDS - High encryption level"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword" -Value 1 -Type DWord `
    -Description "WN22-CC-000460: RDS - Always prompt for password"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fDisableCdm" -Value 1 -Type DWord `
    -Description "WN22-CC-000470: RDS - Disable drive redirection"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "SecurityLayer" -Value 2 -Type DWord `
    -Description "WN22-CC-000480: RDS - SSL/TLS security layer"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "UserAuthentication" -Value 1 -Type DWord `
    -Description "WN22-CC-000490: RDS - Require NLA"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "DeleteTempDirsOnExit" -Value 1 -Type DWord `
    -Description "WN22-CC-000500: RDS - Delete temp folders on exit"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "PerSessionTempDir" -Value 1 -Type DWord `
    -Description "WN22-CC-000510: RDS - Use temp folders per session"

Write-Log "`n=== PowerShell Settings ===" "INFO"

# PowerShell Logging
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord `
    -Description "WN22-CC-000520: PowerShell Script Block Logging"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -Value 1 -Type DWord `
    -Description "WN22-CC-000530: PowerShell Transcription"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell\Transcripts" -Type String `
    -Description "WN22-CC-000540: PowerShell Transcript output directory"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableInvocationHeader" -Value 1 -Type DWord `
    -Description "WN22-CC-000550: PowerShell Transcript invocation headers"

Write-Log "`n=== Event Log Settings ===" "INFO"

# Event Log Sizes
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
    -Name "MaxSize" -Value 32768 -Type DWord `
    -Description "WN22-CC-000560: Application log size"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -Name "MaxSize" -Value 1024000 -Type DWord `
    -Description "WN22-CC-000570: Security log size (1 GB)"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
    -Name "MaxSize" -Value 32768 -Type DWord `
    -Description "WN22-CC-000580: System log size"

# Include command line in process creation events
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord `
    -Description "WN22-CC-000590: Include command line in process events"

Write-Log "`n=== Windows Firewall ===" "INFO"

# Firewall Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000600: Firewall - Domain profile enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -Name "DefaultInboundAction" -Value 1 -Type DWord `
    -Description "WN22-CC-000610: Firewall - Domain inbound blocked"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFilePath" -Value "C:\Windows\System32\logfiles\firewall\domainfw.log" -Type String `
    -Description "WN22-CC-000620: Firewall - Domain log path"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogFileSize" -Value 16384 -Type DWord `
    -Description "WN22-CC-000630: Firewall - Domain log size"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -Name "LogDroppedPackets" -Value 1 -Type DWord `
    -Description "WN22-CC-000640: Firewall - Domain log dropped packets"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000650: Firewall - Private profile enabled"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -Name "EnableFirewall" -Value 1 -Type DWord `
    -Description "WN22-CC-000660: Firewall - Public profile enabled"

Write-Log "`n=== BitLocker Settings ===" "INFO"

# BitLocker Configuration
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseAdvancedStartup" -Value 1 -Type DWord `
    -Description "WN22-CC-000670: BitLocker - Additional authentication at startup"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPMPIN" -Value 1 -Type DWord `
    -Description "WN22-CC-000680: BitLocker - Require TPM PIN"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "MinimumPIN" -Value 6 -Type DWord `
    -Description "WN22-CC-000690: BitLocker - Minimum PIN length"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "UseTPM" -Value 2 -Type DWord `
    -Description "WN22-CC-000700: BitLocker - Do not allow TPM only"

Write-Log "`n=== Credential Guard & Device Guard ===" "INFO"

# Virtualization Based Security
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord `
    -Description "WN22-CC-000710: Enable VBS"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord `
    -Description "WN22-CC-000720: Require Platform Security Features"

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
    -Name "LsaCfgFlags" -Value 1 -Type DWord `
    -Description "WN22-CC-000730: Enable Credential Guard"

# Disable unnecessary services
$servicesToDisable = @(
    "RemoteRegistry",
    "FTPSVC"  # Disable if not using IIS FTP (use external FTP server if needed)
)

foreach ($service in $servicesToDisable) {
    if (!$WhatIf) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled
                Write-Log "SUCCESS: Disabled service: $service" "SUCCESS"
            }
        }
        catch {
            Write-Log "WARNING: Could not disable service $service : $_" "WARN"
        }
    }
}

Write-Log "`n========================================" "INFO"
Write-Log "Windows Server 2022 STIG Application Completed" "SUCCESS"
Write-Log "========================================" "INFO"
Write-Log "`nLog file: $script:LogFile" "INFO"
Write-Log "`nIMPORTANT: A system restart is required." "WARN"
Write-Log "IMPORTANT: Review log for any errors." "WARN"
Write-Log "IMPORTANT: Configure FTP server settings separately." "WARN"
Write-Log "IMPORTANT: Verify BitLocker and Credential Guard status after reboot." "WARN"
