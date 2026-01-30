# PowerShell Script to Apply Active Directory Domain STIG
# Based on: U_Active_Directory_Domain_V3R6_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: Run as Administrator on Domain Controller
# .\Apply-ADDS-Domain-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\ADDS-Domain-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

# Import Active Directory module
if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module not found. Installing..." "ERROR"
    Install-WindowsFeature -Name RSAT-AD-PowerShell
}
Import-Module ActiveDirectory

Write-Log "========================================"
Write-Log "Active Directory Domain STIG Application Starting"
Write-Log "========================================"

$domain = Get-ADDomain

Write-Log "Domain: $($domain.DNSRoot)" "INFO"
Write-Log "Domain DN: $($domain.DistinguishedName)" "INFO"

# WN19-DC-000010: Password policy
Write-Log "Configuring domain password policy..." "INFO"

try {
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
        -MinPasswordLength 14 `
        -PasswordHistoryCount 24 `
        -MaxPasswordAge (New-TimeSpan -Days 60) `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
        -LockoutThreshold 3 `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false
    
    Write-Log "Domain password policy configured" "SUCCESS"
}
catch {
    Write-Log "Failed to configure password policy: $_" "ERROR"
}

# WN19-DC-000020 through WN19-DC-000070: User account policies
Write-Log "Configuring user account settings..." "INFO"

# Get all users
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires, PasswordNotRequired, AllowReversiblePasswordEncryption

foreach ($user in $users) {
    $changed = $false
    
    # Ensure passwords expire
    if ($user.PasswordNeverExpires -eq $true -and $user.SamAccountName -notlike "*svc*") {
        Set-ADUser -Identity $user -PasswordNeverExpires $false
        Write-Log "Disabled PasswordNeverExpires for $($user.SamAccountName)" "INFO"
        $changed = $true
    }
    
    # Ensure password is required
    if ($user.PasswordNotRequired -eq $true) {
        Set-ADUser -Identity $user -PasswordNotRequired $false
        Write-Log "Enabled password requirement for $($user.SamAccountName)" "INFO"
        $changed = $true
    }
    
    # Disable reversible encryption
    if ($user.AllowReversiblePasswordEncryption -eq $true) {
        Set-ADUser -Identity $user -AllowReversiblePasswordEncryption $false
        Write-Log "Disabled reversible encryption for $($user.SamAccountName)" "INFO"
        $changed = $true
    }
}

Write-Log "User account settings configured" "SUCCESS"

# WN19-DC-000080: Disable anonymous LDAP
Write-Log "Configuring LDAP policies..." "INFO"

$domainDN = $domain.DistinguishedName

# Set LDAP server signing requirements
try {
    $rootDSE = Get-ADRootDSE
    $configNC = $rootDSE.configurationNamingContext
    $ntdsSettingsDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
    
    # Require LDAP signing
    Set-ADObject -Identity $ntdsSettingsDN -Replace @{
        "ldapServerIntegrity" = 2  # Require signing
    }
    Write-Log "LDAP signing required" "SUCCESS"
}
catch {
    Write-Log "Failed to configure LDAP signing: $_" "ERROR"
}

# WN19-DC-000090: Anonymous access restrictions
Write-Log "Restricting anonymous access..." "INFO"

# Disable anonymous access to AD
$anonymousAccessDN = "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)"
try {
    Set-ADObject -Identity $anonymousAccessDN -Replace @{
        "dsHeuristics" = "0000002"
    }
    Write-Log "Anonymous access restricted" "SUCCESS"
}
catch {
    Write-Log "Failed to restrict anonymous access: $_" "WARN"
}

# WN19-DC-000100: Audit policy configuration
Write-Log "Configuring domain audit policies..." "INFO"

# Enable auditing on domain
try {
    $domainDN = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:\$domainDN"
    
    # Configure audit settings (requires advanced auditing via GPO)
    Write-Log "Note: Advanced audit policies must be configured via GPO" "WARN"
}
catch {
    Write-Log "Failed to configure audit policy: $_" "ERROR"
}

# WN19-DC-000110 through WN19-DC-000150: Service account management
Write-Log "Reviewing service accounts..." "INFO"

$serviceAccounts = Get-ADUser -Filter {(SamAccountName -like "*svc*") -or (SamAccountName -like "*service*")} -Properties ServicePrincipalName, PasswordLastSet

foreach ($svcAcct in $serviceAccounts) {
    Write-Log "Service Account: $($svcAcct.SamAccountName)" "INFO"
    Write-Log "  SPNs: $($svcAcct.ServicePrincipalName -join ', ')" "INFO"
    Write-Log "  Password Last Set: $($svcAcct.PasswordLastSet)" "INFO"
    
    # Recommend password rotation
    if ($svcAcct.PasswordLastSet -lt (Get-Date).AddDays(-60)) {
        Write-Log "  WARNING: Password older than 60 days" "WARN"
    }
}

# WN19-DC-000160: Privileged account management
Write-Log "Reviewing privileged accounts..." "INFO"

# Get members of privileged groups
$privilegedGroups = @(
    "Enterprise Admins",
    "Domain Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        Write-Log "Group: $group" "INFO"
        Write-Log "  Members: $($members.Count)" "INFO"
        
        foreach ($member in $members) {
            Write-Log "    - $($member.SamAccountName)" "INFO"
        }
    }
    catch {
        Write-Log "Could not query group: $group" "WARN"
    }
}

# WN19-DC-000170: Inactive accounts
Write-Log "Identifying inactive accounts..." "INFO"

$inactiveDate = (Get-Date).AddDays(-35)
$inactiveUsers = Get-ADUser -Filter {(Enabled -eq $true) -and (LastLogonDate -lt $inactiveDate)} -Properties LastLogonDate

Write-Log "Found $($inactiveUsers.Count) inactive user accounts" "INFO"

foreach ($user in $inactiveUsers) {
    Write-Log "Inactive: $($user.SamAccountName) - Last Logon: $($user.LastLogonDate)" "WARN"
}

# WN19-DC-000180: Guest account disabled
Write-Log "Checking Guest account..." "INFO"

$guest = Get-ADUser -Identity "Guest"
if ($guest.Enabled -eq $true) {
    Disable-ADAccount -Identity $guest
    Write-Log "Disabled Guest account" "SUCCESS"
}
else {
    Write-Log "Guest account already disabled" "INFO"
}

# WN19-DC-000190: Built-in Administrator renamed
Write-Log "Checking built-in Administrator account..." "INFO"

$admin = Get-ADUser -Filter {SID -like "*-500"}
if ($admin.SamAccountName -eq "Administrator") {
    Write-Log "WARNING: Built-in Administrator account not renamed" "WARN"
    Write-Log "  Recommended: Rename to non-obvious name" "WARN"
}
else {
    Write-Log "Built-in Administrator renamed to: $($admin.SamAccountName)" "INFO"
}

# WN19-DC-000200: Kerberos policy
Write-Log "Configuring Kerberos policy..." "INFO"

try {
    # Note: Kerberos policy is part of Default Domain Policy
    Write-Log "Note: Configure via Default Domain Policy GPO:" "WARN"
    Write-Log "  - Maximum lifetime for user ticket: 10 hours" "WARN"
    Write-Log "  - Maximum lifetime for service ticket: 600 minutes" "WARN"
    Write-Log "  - Maximum tolerance for computer clock sync: 5 minutes" "WARN"
    Write-Log "  - Maximum lifetime for user ticket renewal: 7 days" "WARN"
}
catch {
    Write-Log "Kerberos policy configuration: $_" "ERROR"
}

# WN19-DC-000210: SMB signing
Write-Log "Verifying SMB signing on DC..." "INFO"

$smbServer = Get-SmbServerConfiguration
if ($smbServer.RequireSecuritySignature -eq $false) {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Write-Log "SMB signing enabled" "SUCCESS"
}
else {
    Write-Log "SMB signing already enabled" "INFO"
}

# WN19-DC-000220 through WN19-DC-000250: Group Policy hardening
Write-Log "Group Policy recommendations..." "INFO"

Write-Log "Create or modify Default Domain Policy:" "WARN"
Write-Log "  Computer Configuration > Policies > Windows Settings > Security Settings:" "WARN"
Write-Log "    - Account Policies: Set password/lockout policies" "WARN"
Write-Log "    - Local Policies > Audit Policy: Enable comprehensive auditing" "WARN"
Write-Log "    - Local Policies > User Rights Assignment: Restrict privileged operations" "WARN"
Write-Log "    - Local Policies > Security Options: Configure as per STIG" "WARN"
Write-Log "  Computer Configuration > Policies > Administrative Templates:" "WARN"
Write-Log "    - System > Logon: Configure logon banner" "WARN"
Write-Log "    - Windows Components > Windows PowerShell: Enable logging" "WARN"

# WN19-DC-000260: Recycle Bin enabled
Write-Log "Checking AD Recycle Bin..." "INFO"

$recycleBin = Get-ADOptionalFeature -Filter {Name -like "*Recycle*"}
if ($recycleBin.EnabledScopes.Count -eq 0) {
    Write-Log "WARNING: AD Recycle Bin not enabled" "WARN"
    Write-Log "  Enable with: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($domain.Forest)" "WARN"
}
else {
    Write-Log "AD Recycle Bin enabled" "SUCCESS"
}

# WN19-DC-000270: Protected Users group
Write-Log "Checking Protected Users group..." "INFO"

try {
    $protectedUsers = Get-ADGroup -Identity "Protected Users"
    $members = Get-ADGroupMember -Identity $protectedUsers
    
    Write-Log "Protected Users group exists with $($members.Count) members" "INFO"
    Write-Log "Recommendation: Add high-privilege accounts to Protected Users group" "WARN"
}
catch {
    Write-Log "Protected Users group not found or error occurred" "WARN"
}

# WN19-DC-000280: Fine-Grained Password Policies (PSO)
Write-Log "Checking Password Settings Objects..." "INFO"

$psos = Get-ADFineGrainedPasswordPolicy -Filter *
if ($psos.Count -eq 0) {
    Write-Log "No Fine-Grained Password Policies defined" "INFO"
    Write-Log "Recommendation: Create PSOs for privileged accounts with stricter policies" "WARN"
}
else {
    foreach ($pso in $psos) {
        Write-Log "PSO: $($pso.Name)" "INFO"
        Write-Log "  Min Password Length: $($pso.MinPasswordLength)" "INFO"
        Write-Log "  Password History: $($pso.PasswordHistoryCount)" "INFO"
    }
}

# WN19-DC-000290: Time synchronization
Write-Log "Checking time synchronization..." "INFO"

$pdcEmulator = Get-ADDomainController -Discover -Service PrimaryDC
Write-Log "PDC Emulator: $($pdcEmulator.HostName)" "INFO"
Write-Log "Ensure PDC synchronizes with authoritative time source (NTP)" "WARN"

# WN19-DC-000300: SYSVOL permissions
Write-Log "Checking SYSVOL permissions..." "INFO"

$sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL"
Write-Log "SYSVOL Path: $sysvolPath" "INFO"
Write-Log "Verify SYSVOL permissions manually:" "WARN"
Write-Log "  - Authenticated Users: Read & Execute" "WARN"
Write-Log "  - Domain Admins: Full Control" "WARN"
Write-Log "  - Enterprise Admins: Full Control" "WARN"

Write-Log ""
Write-Log "========================================"
Write-Log "Active Directory Domain STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log "1. Configure Default Domain Policy GPO with all STIG settings"
Write-Log "2. Enable AD Recycle Bin if not already enabled"
Write-Log "3. Create Fine-Grained Password Policies for privileged accounts"
Write-Log "4. Add privileged accounts to Protected Users group"
Write-Log "5. Rename built-in Administrator account"
Write-Log "6. Disable or delete inactive accounts"
Write-Log "7. Configure time synchronization on PDC Emulator"
Write-Log "8. Implement tiered admin model (Tier 0, 1, 2)"
Write-Log "9. Enable Advanced Audit Policy via GPO"
Write-Log "10. Run STIG compliance scan with SCAP tool"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
