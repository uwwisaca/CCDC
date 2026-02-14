<#
.SYNOPSIS
    Windows Server 2022 STIG - Module 3: Security Options
.DESCRIPTION
    Configures security options including UAC, legal notices, LSA protection
    Based on U_MS_Windows_Server_2022_V2R7_Manual_STIG
.NOTES
    Version: 1.0
    Date: February 12, 2026
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Continue'
$LogFile = "C:\Windows\Logs\STIG-Module03-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\STIG-Backups\Module03-Security-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
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

Write-Log "========================================" "INFO"
Write-Log "Module 3: Security Options" "INFO"
Write-Log "========================================" "INFO"

# Create backup
if (!$WhatIf) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" "$BackupDir\Policies.reg" /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupDir\LSA.reg" /y | Out-Null
    Write-Log "Backup created: $BackupDir" "SUCCESS"
}

# Legal Notice
Write-Log "Configuring legal notice..." "INFO"

$legalNoticeText = @"
═══════════════════════════════════════════════════════════════
                        WINDOWS LEGAL NOTICE
═══════════════════════════════════════════════════════════════

According to all known laws of information technology,
there is no way this Windows server should be able to run.
Its registry is too bloated to get its fat little processes
off the ground. The server, of course, runs anyway,
because Windows doesn't care what IT professionals think is impossible.

Yellow, black. Yellow, black. Yellow, black. Yellow, black.
Ooh, black and yellow! Let's shake it up a little.

Barry! Login attempt denied. You ready?

Ready? I've been ready my whole Active Directory lifecycle.
I've got three passwords, five MFA tokens, and I still can't access
the file share.

You think these credential prompts are funny?
I think they're funny. They're hilarious!

You know what your problem is, Barry?
I gotta start thinking bee—I mean USER!

Here she comes! Speak, you fool!
...Hi!
...ACCOUNT LOCKED DUE TO INACTIVITY

What was that? Maybe this whole workstation authorization thing
isn't for me. You wanna do what everyone else is doing?
I wanna do MY part for the domain! I've got to!

You snap out of it! You're flying outside the hive! 
You're in the GUEST account, Barry!

Barry, I told you, stop flying through the Group Policy!

- Ooh, should I start it up? Look at me starting Windows Update!
- No! Don't start Windows Update! It'll take 4 hours!
- Too late! Installing update 1 of 247...

You know, Dad, the more I think about it,
maybe the Network Administrator isn't just about 
rebooting servers and clearing print queues.

Son, let me tell you about Active Directory...
(12 HOURS OF DIALOGUE LATER)

So you're saying that NTLM authentication is—
OBSOLETE, BARRY! WE'VE BEEN USING KERBEROS SINCE 2003!

I gotta say something. She saved my session!
I'm gonna remember you as the sysadmin who 
restored from backup!

This isn't so hard. [BOOM] BLUE SCREEN OF DEATH
Wow! I'm out! I can't believe I'm out of Safe Mode!

What were we thinking?! Look at us. We're just Windows users!
We're the most perfectly functioning society on Earth—
CRITICAL ERROR: SYSTEM32 NOT FOUND

According to all known laws of IT support,
your login credentials have expired.
Please contact the Help Desk.
Estimated wait time: FOREVER.

Barry, you are so funny sometimes!
I'm not trying to be funny!
You're not funny! You're going into Honey—I MEAN ADMIN MODE!

NOTICE: Unauthorized access will result in:
✓ Being stuck in an infinite UAC prompt loop
✓ Your desktop being changed to the Windows XP bliss wallpaper
✓ Mandatory Bing as default search engine
✓ All your shortcuts replaced with Internet Explorer
✓ Your computer name changed to "Barry-Benson-Workstation"

Press any key to continue
(Where's the "any" key?!)

═══════════════════════════════════════════════════════════════
           Ya like JAZZ? Well, ya like ACTIVE DIRECTORY?!
═══════════════════════════════════════════════════════════════
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
    -Description "WN22-SO-000120: Machine inactivity limit (15 minutes)"

# UAC Settings
Write-Log "Configuring UAC settings..." "INFO"

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

# LSA Protection
Write-Log "Configuring LSA protection..." "INFO"

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
    -Description "WN22-SO-000190: LAN Manager authentication level (NTLMv2 only)"

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

Write-Log "" "INFO"
Write-Log "========================================" "SUCCESS"
Write-Log "Module 3 Completed: Security Options" "SUCCESS"
Write-Log "========================================" "SUCCESS"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "Backup: $BackupDir" "INFO"
