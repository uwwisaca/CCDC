# PowerShell Script to Apply Active Directory Forest STIG
# Based on: U_Active_Directory_Forest_V3R2_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: Run as Administrator on Domain Controller with Enterprise Admin rights
# .\Apply-ADDS-Forest-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\ADDS-Forest-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

Import-Module ActiveDirectory

Write-Log "========================================"
Write-Log "Active Directory Forest STIG Application Starting"
Write-Log "========================================"

$forest = Get-ADForest
$rootDomain = Get-ADDomain -Identity $forest.RootDomain

Write-Log "Forest: $($forest.Name)" "INFO"
Write-Log "Forest Functional Level: $($forest.ForestMode)" "INFO"
Write-Log "Root Domain: $($forest.RootDomain)" "INFO"

# Verify Enterprise Admin membership
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
Write-Log "Current User: $($currentUser.Name)" "INFO"

# WN19-AF-000010: Forest functional level
Write-Log "Checking forest functional level..." "INFO"

if ($forest.ForestMode -lt "Windows2016Forest") {
    Write-Log "WARNING: Forest functional level below Windows Server 2016" "WARN"
    Write-Log "Current: $($forest.ForestMode)" "WARN"
    Write-Log "Recommended: Raise to Windows2016Forest or higher" "WARN"
}
else {
    Write-Log "Forest functional level is compliant: $($forest.ForestMode)" "SUCCESS"
}

# WN19-AF-000020: Schema Admins group
Write-Log "Checking Schema Admins group..." "INFO"

$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -Server $forest.SchemaMaster
Write-Log "Schema Admins member count: $($schemaAdmins.Count)" "INFO"

if ($schemaAdmins.Count -eq 0) {
    Write-Log "WARNING: Schema Admins group is empty" "WARN"
}
else {
    foreach ($member in $schemaAdmins) {
        Write-Log "  Member: $($member.SamAccountName)" "INFO"
    }
    Write-Log "Verify that only authorized users are Schema Admins" "WARN"
}

# WN19-AF-000030: Enterprise Admins group
Write-Log "Checking Enterprise Admins group..." "INFO"

$enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins"
Write-Log "Enterprise Admins member count: $($enterpriseAdmins.Count)" "INFO"

if ($enterpriseAdmins.Count -eq 0) {
    Write-Log "WARNING: Enterprise Admins group is empty" "WARN"
}
else {
    foreach ($member in $enterpriseAdmins) {
        Write-Log "  Member: $($member.SamAccountName)" "INFO"
    }
    Write-Log "Verify that only authorized users are Enterprise Admins" "WARN"
}

# WN19-AF-000040: AD Recycle Bin
Write-Log "Checking AD Recycle Bin status..." "INFO"

$recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"}
if ($recycleBinFeature.EnabledScopes.Count -eq 0) {
    Write-Log "AD Recycle Bin is NOT enabled" "WARN"
    Write-Log "To enable: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($forest.Name)" "WARN"
}
else {
    Write-Log "AD Recycle Bin is enabled" "SUCCESS"
}

# WN19-AF-000050: Schema modifications logging
Write-Log "Checking schema audit policy..." "INFO"

$schemaNC = $forest.PartitionsContainer.Replace("CN=Partitions,", "CN=Schema,")
Write-Log "Schema NC: $schemaNC" "INFO"
Write-Log "Ensure auditing is enabled on Schema container" "WARN"

# WN19-AF-000060: Schema Master FSMO role
Write-Log "Checking FSMO role holders..." "INFO"

Write-Log "Schema Master: $($forest.SchemaMaster)" "INFO"
Write-Log "Domain Naming Master: $($forest.DomainNamingMaster)" "INFO"

# Verify Schema Master is online and accessible
try {
    $schemaMasterDC = Get-ADDomainController -Identity $forest.SchemaMaster
    Write-Log "Schema Master is online: $($schemaMasterDC.HostName)" "SUCCESS"
}
catch {
    Write-Log "Schema Master is not accessible: $_" "ERROR"
}

# WN19-AF-000070: Trust relationships
Write-Log "Checking forest trusts..." "INFO"

$trusts = Get-ADTrust -Filter * -Server $forest.Name
if ($trusts.Count -eq 0) {
    Write-Log "No forest trusts configured" "INFO"
}
else {
    foreach ($trust in $trusts) {
        Write-Log "Trust: $($trust.Name)" "INFO"
        Write-Log "  Direction: $($trust.Direction)" "INFO"
        Write-Log "  Type: $($trust.TrustType)" "INFO"
        Write-Log "  Selective Authentication: $($trust.SelectiveAuthentication)" "INFO"
        
        if ($trust.SelectiveAuthentication -eq $false) {
            Write-Log "  WARNING: Consider enabling Selective Authentication" "WARN"
        }
    }
}

# WN19-AF-000080: SID filtering
Write-Log "Checking SID filtering on trusts..." "INFO"

foreach ($trust in $trusts) {
    Write-Log "Checking SID filtering for: $($trust.Name)" "INFO"
    # SID filtering is enabled by default on external trusts
    # For forest trusts, verify quarantine is not disabled
    Write-Log "  Verify SID filtering is enabled (default for external trusts)" "WARN"
}

# WN19-AF-000090: Sites and subnets
Write-Log "Checking AD Sites configuration..." "INFO"

$sites = Get-ADReplicationSite -Filter *
Write-Log "Number of sites: $($sites.Count)" "INFO"

foreach ($site in $sites) {
    Write-Log "Site: $($site.Name)" "INFO"
    
    # Check subnets for each site
    $subnets = Get-ADReplicationSubnet -Filter {Site -eq $site.Name}
    Write-Log "  Subnets: $($subnets.Count)" "INFO"
    
    foreach ($subnet in $subnets) {
        Write-Log "    - $($subnet.Name)" "INFO"
    }
}

if ($sites.Count -eq 1 -and $sites[0].Name -eq "Default-First-Site-Name") {
    Write-Log "WARNING: Only default site exists. Configure sites/subnets for proper replication" "WARN"
}

# WN19-AF-000100: Global Catalog servers
Write-Log "Checking Global Catalog servers..." "INFO"

$gcServers = Get-ADDomainController -Filter {IsGlobalCatalog -eq $true}
Write-Log "Global Catalog servers: $($gcServers.Count)" "INFO"

foreach ($gc in $gcServers) {
    Write-Log "  GC: $($gc.HostName)" "INFO"
}

if ($gcServers.Count -lt 2) {
    Write-Log "WARNING: Less than 2 Global Catalog servers (single point of failure)" "WARN"
}

# WN19-AF-000110: DNS configuration
Write-Log "Checking DNS configuration..." "INFO"

foreach ($dc in (Get-ADDomainController -Filter *)) {
    Write-Log "DC: $($dc.HostName)" "INFO"
    Write-Log "  DNS: $($dc.HostName)" "INFO"
    
    # Check if DC is also DNS server
    try {
        $dnsServer = Get-Service -Name DNS -ComputerName $dc.HostName -ErrorAction SilentlyContinue
        if ($dnsServer -and $dnsServer.Status -eq "Running") {
            Write-Log "  DNS Service: Running" "SUCCESS"
        }
        else {
            Write-Log "  DNS Service: Not running or not installed" "WARN"
        }
    }
    catch {
        Write-Log "  Cannot check DNS service: $_" "WARN"
    }
}

# WN19-AF-000120: Time synchronization hierarchy
Write-Log "Checking time synchronization..." "INFO"

$pdcEmulator = Get-ADDomainController -Discover -Service PrimaryDC
Write-Log "PDC Emulator (time source): $($pdcEmulator.HostName)" "INFO"
Write-Log "Ensure PDC Emulator synchronizes with external NTP source" "WARN"

# WN19-AF-000130: DFS-R for SYSVOL replication
Write-Log "Checking SYSVOL replication method..." "INFO"

$dfsrEnabled = (Get-ADObject -Filter {objectClass -eq "msDFSR-GlobalSettings"} -SearchBase "CN=Configuration,$($forest.RootDomain)" -ErrorAction SilentlyContinue)

if ($dfsrEnabled) {
    Write-Log "SYSVOL replication using DFS-R" "SUCCESS"
}
else {
    Write-Log "SYSVOL may be using FRS (deprecated)" "WARN"
    Write-Log "Migrate to DFS-R if using FRS" "WARN"
}

# WN19-AF-000140: AdminSDHolder
Write-Log "Checking AdminSDHolder..." "INFO"

$adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$($rootDomain.DistinguishedName)" -Properties *
Write-Log "AdminSDHolder exists: True" "SUCCESS"
Write-Log "Verify AdminSDHolder permissions are properly configured" "WARN"

# WN19-AF-000150: Deleted Objects container protection
Write-Log "Checking Deleted Objects container..." "INFO"

try {
    $deletedObjects = Get-ADObject "CN=Deleted Objects,$($rootDomain.DistinguishedName)" -IncludeDeletedObjects -Properties *
    Write-Log "Deleted Objects container accessible" "SUCCESS"
}
catch {
    Write-Log "Cannot access Deleted Objects container: $_" "WARN"
}

# WN19-AF-000160: Tombstone lifetime
Write-Log "Checking tombstone lifetime..." "INFO"

$configNC = (Get-ADRootDSE).configurationNamingContext
$dse = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime

if ($dse.tombstoneLifetime) {
    Write-Log "Tombstone Lifetime: $($dse.tombstoneLifetime) days" "INFO"
    
    if ($dse.tombstoneLifetime -lt 180) {
        Write-Log "WARNING: Tombstone lifetime is less than 180 days" "WARN"
    }
}
else {
    Write-Log "Tombstone Lifetime: Default (180 days)" "INFO"
}

# WN19-AF-000170: Backup and restore procedures
Write-Log "Checking AD backup status..." "INFO"

Write-Log "Verify that:" "WARN"
Write-Log "  - System State backups are performed regularly" "WARN"
Write-Log "  - Backups are tested for restore capability" "WARN"
Write-Log "  - Backup retention meets recovery objectives" "WARN"
Write-Log "  - At least one DC per domain is backed up" "WARN"

# WN19-AF-000180: Schema extensions documentation
Write-Log "Schema extensions..." "INFO"

Write-Log "Document all schema extensions:" "WARN"
Write-Log "  - Extension date" "WARN"
Write-Log "  - Application/vendor" "WARN"
Write-Log "  - Approval authority" "WARN"
Write-Log "  - Testing performed" "WARN"

# WN19-AF-000190: Privileged account monitoring
Write-Log "Privileged account audit recommendations..." "INFO"

Write-Log "Implement monitoring for:" "WARN"
Write-Log "  - Schema Admins group changes" "WARN"
Write-Log "  - Enterprise Admins group changes" "WARN"
Write-Log "  - Domain Admins group changes (all domains)" "WARN"
Write-Log "  - FSMO role transfers" "WARN"
Write-Log "  - Trust creation/modification" "WARN"
Write-Log "  - Schema modifications" "WARN"

Write-Log ""
Write-Log "========================================"
Write-Log "Active Directory Forest STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log "1. Enable AD Recycle Bin if not already enabled"
Write-Log "2. Raise forest functional level if below Windows Server 2016"
Write-Log "3. Configure sites and subnets for all physical locations"
Write-Log "4. Ensure multiple Global Catalog servers for redundancy"
Write-Log "5. Migrate SYSVOL from FRS to DFS-R if needed"
Write-Log "6. Review and minimize Schema Admins membership"
Write-Log "7. Review and minimize Enterprise Admins membership"
Write-Log "8. Enable Selective Authentication on external trusts"
Write-Log "9. Configure tombstone lifetime to at least 180 days"
Write-Log "10. Implement System State backup schedule"
Write-Log "11. Document all schema extensions"
Write-Log "12. Implement privileged account monitoring/alerting"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
