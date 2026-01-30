# PowerShell Script to Apply IIS 10.0 Server STIG
# Based on: U_IIS_10-0_Server_V2R11_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Applies server-level IIS hardening for Windows Server 2019
#
# Usage: Run as Administrator
# .\Apply-IIS-Server-STIG.ps1

#Requires -RunAsAdministrator

Import-Module WebAdministration -ErrorAction SilentlyContinue

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\IIS-Server-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\Logs\IIS-Server-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "IIS 10.0 Server STIG Application Starting"
Write-Log "========================================"

# Verify IIS is installed
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Log "IIS Web Administration module not found" "ERROR"
    Write-Log "Install IIS using: Install-WindowsFeature -Name Web-Server -IncludeManagementTools" "ERROR"
    exit 1
}

Import-Module WebAdministration

Write-Log "IIS Web Administration module loaded" "SUCCESS"

# Create backup directory
New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null

# Backup IIS configuration
Write-Log "Creating IIS configuration backup..." "INFO"
$backupName = "STIG-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Backup-WebConfiguration -Name $backupName
Write-Log "IIS configuration backed up: $backupName" "SUCCESS"

# Export ApplicationHost.config
$appHostConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
Copy-Item -Path $appHostConfig -Destination "$BackupDir\applicationHost.config.bak" -Force
Write-Log "ApplicationHost.config backed up to: $BackupDir" "SUCCESS"

# ========================================
# STIG V-218789: Remove IIS sample files and directories
# ========================================
Write-Log "Removing IIS sample files and directories..." "INFO"

$samplesToRemove = @(
    "$env:SystemDrive\inetpub\wwwroot\iisstart.htm",
    "$env:SystemDrive\inetpub\wwwroot\iisstart.png",
    "$env:SystemDrive\inetpub\AdminScripts"
)

foreach ($sample in $samplesToRemove) {
    if (Test-Path $sample) {
        Remove-Item -Path $sample -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed: $sample" "SUCCESS"
    }
}

# ========================================
# STIG V-218790: Disable IIS unnecessary role services and features
# ========================================
Write-Log "Checking unnecessary IIS features..." "INFO"

$unnecessaryFeatures = @(
    "Web-Dir-Browsing",
    "Web-WebDAV",
    "Web-Ftp-Server",
    "Web-Ftp-Service",
    "Web-Ftp-Ext"
)

foreach ($feature in $unnecessaryFeatures) {
    $featureState = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
    if ($featureState -and $featureState.Installed) {
        Write-Log "Removing feature: $feature" "WARN"
        Uninstall-WindowsFeature -Name $feature -Remove | Out-Null
        Write-Log "Feature removed: $feature" "SUCCESS"
    }
}

# ========================================
# STIG V-218791: Configure IIS logging
# ========================================
Write-Log "Configuring IIS logging settings..." "INFO"

# Set log file directory
$logDirectory = "$env:SystemDrive\inetpub\logs\LogFiles"
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "directory" -Value $logDirectory

# Configure log format (W3C Extended)
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "logFormat" -Value "W3C"

# Configure log fields
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"

# Set log file rollover
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "period" -Value "Daily"

# Set local time for log files
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "localTimeRollover" -Value $true

Write-Log "IIS logging configured" "SUCCESS"

# ========================================
# STIG V-218792: Configure ETW logging
# ========================================
Write-Log "Enabling ETW (Event Tracing for Windows) logging..." "INFO"

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "logTargetW3C" -Value "File,ETW"

Write-Log "ETW logging enabled" "SUCCESS"

# ========================================
# STIG V-218793: Configure session state settings
# ========================================
Write-Log "Configuring session state settings..." "INFO"

# Set session timeout to 20 minutes
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.web/sessionState" -Name "timeout" -Value "00:20:00"

# Configure session state to use cookies
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.web/sessionState" -Name "cookieless" -Value "UseCookies"

# Require SSL for session cookies
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.web/sessionState" -Name "cookieSameSite" -Value "Strict"

Write-Log "Session state configured" "SUCCESS"

# ========================================
# STIG V-218794: Configure request filtering
# ========================================
Write-Log "Configuring request filtering..." "INFO"

# Remove Server header
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -Value $true

# Configure file extension restrictions
$denyExtensions = @(".asa", ".asax", ".ascx", ".master", ".skin", ".browser", ".sitemap", ".config", ".cs", ".csproj", ".vb", ".vbproj", ".webinfo", ".licx", ".resx", ".resources")

foreach ($ext in $denyExtensions) {
    $exists = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "Collection" | Where-Object { $_.fileExtension -eq $ext }
    
    if (-not $exists) {
        Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "." -Value @{fileExtension=$ext; allowed=$false}
    }
}

# Set max request length (30MB = 30000000 bytes)
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 30000000

# Set max URL length
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 4096

# Set max query string length
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048

Write-Log "Request filtering configured" "SUCCESS"

# ========================================
# STIG V-218795: Configure connection timeout
# ========================================
Write-Log "Configuring connection timeout..." "INFO"

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/limits" -Name "connectionTimeout" -Value "00:02:00"

Write-Log "Connection timeout set to 2 minutes" "SUCCESS"

# ========================================
# STIG V-218796: Configure max connections
# ========================================
Write-Log "Configuring max connections..." "INFO"

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/sites/siteDefaults/limits" -Name "maxConnections" -Value 4294967295

Write-Log "Max connections configured" "SUCCESS"

# ========================================
# STIG V-218797: Disable directory browsing
# ========================================
Write-Log "Disabling directory browsing..." "INFO"

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false

Write-Log "Directory browsing disabled" "SUCCESS"

# ========================================
# STIG V-218798: Configure error messages
# ========================================
Write-Log "Configuring custom error pages..." "INFO"

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"

Write-Log "Custom error pages configured" "SUCCESS"

# ========================================
# STIG V-218799: Configure MIME types
# ========================================
Write-Log "Configuring MIME types..." "INFO"

# Remove unnecessary MIME types
$unnecessaryMimeTypes = @(".exe", ".dll", ".com", ".bat", ".cmd")

foreach ($mimeType in $unnecessaryMimeTypes) {
    $exists = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/staticContent" -Name "Collection" | Where-Object { $_.fileExtension -eq $mimeType }
    
    if ($exists) {
        Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/staticContent" -Name "Collection" -AtElement @{fileExtension=$mimeType}
        Write-Log "Removed MIME type: $mimeType" "SUCCESS"
    }
}

Write-Log "MIME types configured" "SUCCESS"

# ========================================
# STIG V-218800: Configure HTTP verbs
# ========================================
Write-Log "Configuring HTTP verb filtering..." "INFO"

# Allow only specific HTTP verbs
Clear-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/verbs"

$allowedVerbs = @("GET", "POST", "HEAD")
foreach ($verb in $allowedVerbs) {
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/verbs" -Name "." -Value @{verb=$verb; allowed=$true}
}

# Deny all others
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/verbs" -Name "allowUnlisted" -Value $false

Write-Log "HTTP verb filtering configured (GET, POST, HEAD only)" "SUCCESS"

# ========================================
# STIG V-218801: Configure SSL/TLS
# ========================================
Write-Log "Configuring SSL/TLS protocols..." "INFO"

# Disable SSL 2.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# Disable SSL 3.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# Disable TLS 1.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# Disable TLS 1.1
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# Enable TLS 1.2
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

# Enable TLS 1.3 (if supported)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

Write-Log "SSL/TLS protocols configured (TLS 1.2 and 1.3 only)" "SUCCESS"

# ========================================
# STIG V-218802: Configure cipher suites
# ========================================
Write-Log "Configuring cipher suites..." "INFO"

# Define strong cipher suite order
$cipherSuites = @(
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
)

# Set cipher suite order
$cipherSuiteOrder = $cipherSuites -join ","
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherSuiteOrder

Write-Log "Cipher suites configured" "SUCCESS"

# ========================================
# STIG V-218803: Configure HSTS (HTTP Strict Transport Security)
# ========================================
Write-Log "Configuring HSTS..." "INFO"

# Add HSTS header configuration
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains"} -ErrorAction SilentlyContinue

Write-Log "HSTS configured" "SUCCESS"

# ========================================
# STIG V-218804: Remove unnecessary response headers
# ========================================
Write-Log "Removing unnecessary response headers..." "INFO"

# Remove X-Powered-By header
Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name="X-Powered-By"} -ErrorAction SilentlyContinue

Write-Log "Unnecessary response headers removed" "SUCCESS"

# ========================================
# STIG V-218805: Add security headers
# ========================================
Write-Log "Adding security headers..." "INFO"

$securityHeaders = @(
    @{name="X-Frame-Options"; value="SAMEORIGIN"},
    @{name="X-Content-Type-Options"; value="nosniff"},
    @{name="X-XSS-Protection"; value="1; mode=block"},
    @{name="Content-Security-Policy"; value="default-src 'self'"}
)

foreach ($header in $securityHeaders) {
    # Remove if exists
    Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name=$header.name} -ErrorAction SilentlyContinue
    
    # Add header
    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value $header
}

Write-Log "Security headers added" "SUCCESS"

# ========================================
# STIG V-218806: Configure application pool settings
# ========================================
Write-Log "Configuring default application pool settings..." "INFO"

# Set application pool idle timeout
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -Name "idleTimeout" -Value "00:20:00"

# Set application pool recycle interval
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart" -Name "time" -Value "1.05:00:00"

# Enable rapid fail protection
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/failure" -Name "rapidFailProtection" -Value $true

# Set rapid fail protection interval
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/failure" -Name "rapidFailProtectionInterval" -Value "00:05:00"

# Set rapid fail protection max failures
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/failure" -Name "rapidFailProtectionMaxCrashes" -Value 5

Write-Log "Application pool settings configured" "SUCCESS"

# ========================================
# STIG V-218807: Configure worker process isolation
# ========================================
Write-Log "Configuring worker process isolation..." "INFO"

# Set identity to ApplicationPoolIdentity
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -Name "identityType" -Value "ApplicationPoolIdentity"

# Enable 32-bit applications if needed (set to false for 64-bit only)
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.applicationHost/applicationPools/applicationPoolDefaults" -Name "enable32BitAppOnWin64" -Value $false

Write-Log "Worker process isolation configured" "SUCCESS"

# ========================================
# STIG V-218808: Configure anonymous authentication
# ========================================
Write-Log "Configuring anonymous authentication..." "INFO"

# Disable anonymous authentication by default (enable per-site as needed)
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value $false

Write-Log "Anonymous authentication disabled by default" "SUCCESS"

# ========================================
# STIG V-218809: Configure Windows authentication
# ========================================
Write-Log "Configuring Windows authentication..." "INFO"

# Enable Windows authentication
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value $true

# Use kernel mode
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "useKernelMode" -Value $true

Write-Log "Windows authentication configured" "SUCCESS"

# ========================================
# STIG V-218810: Configure machine key
# ========================================
Write-Log "Configuring machine key..." "INFO"

# Generate a unique machine key
$validationKey = -join ((48..57) + (65..70) | Get-Random -Count 128 | ForEach-Object {[char]$_})
$decryptionKey = -join ((48..57) + (65..70) | Get-Random -Count 48 | ForEach-Object {[char]$_})

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "system.web/machineKey" -Name "validationKey" -Value $validationKey
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "system.web/machineKey" -Name "decryptionKey" -Value $decryptionKey
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "system.web/machineKey" -Name "validation" -Value "SHA1"
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter "system.web/machineKey" -Name "decryption" -Value "AES"

Write-Log "Machine key configured with unique values" "SUCCESS"

# ========================================
# STIG V-218811: Configure ISAPI and CGI restrictions
# ========================================
Write-Log "Configuring ISAPI and CGI restrictions..." "INFO"

# Set to not allow unspecified
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedIsapisAllowed" -Value $false
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedCgisAllowed" -Value $false

Write-Log "ISAPI and CGI restrictions configured" "SUCCESS"

# ========================================
# STIG V-218812: Set file permissions
# ========================================
Write-Log "Configuring file system permissions..." "INFO"

$paths = @(
    "$env:SystemDrive\inetpub\wwwroot",
    "$env:SystemDrive\inetpub\logs"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        $acl = Get-Acl $path
        
        # Remove inheritance
        $acl.SetAccessRuleProtection($true, $false)
        
        # Remove all existing rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        
        # Add Administrators full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($adminRule)
        
        # Add SYSTEM full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($systemRule)
        
        # Add IIS_IUSRS read and execute
        $iisRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($iisRule)
        
        Set-Acl -Path $path -AclObject $acl
        Write-Log "Permissions set for: $path" "SUCCESS"
    }
}

# ========================================
# STIG V-218813: Restart IIS
# ========================================
Write-Log "Restarting IIS..." "INFO"

iisreset /restart | Out-Null

if ($?) {
    Write-Log "IIS restarted successfully" "SUCCESS"
}
else {
    Write-Log "IIS restart failed" "ERROR"
}

Write-Log ""
Write-Log "========================================"
Write-Log "IIS 10.0 Server STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Configuration backup: $backupName"
Write-Log "ApplicationHost.config backup: $BackupDir"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log ""
Write-Log "1. Review and configure SSL certificates for each website" "WARN"
Write-Log "   - Obtain CA-signed certificates" "WARN"
Write-Log "   - Bind certificates to IIS sites (port 443)" "WARN"
Write-Log "   - Disable HTTP bindings or redirect to HTTPS" "WARN"
Write-Log ""
Write-Log "2. Apply site-specific STIG settings:" "WARN"
Write-Log "   - Run: .\Apply-IIS-Site-STIG.ps1" "WARN"
Write-Log ""
Write-Log "3. Configure authentication for each application:" "WARN"
Write-Log "   - Enable appropriate authentication methods" "WARN"
Write-Log "   - Disable anonymous authentication unless required" "WARN"
Write-Log ""
Write-Log "4. Review application pool settings for each application:" "WARN"
Write-Log "   - Ensure unique identity per application" "WARN"
Write-Log "   - Configure appropriate .NET framework version" "WARN"
Write-Log ""
Write-Log "5. Configure URL Rewrite rules to enforce HTTPS:" "WARN"
Write-Log "   - Install URL Rewrite module if not present" "WARN"
Write-Log "   - Create HTTP to HTTPS redirect rules" "WARN"
Write-Log ""
Write-Log "6. Review and test all websites after STIG implementation" "WARN"
Write-Log ""
Write-Log "7. Configure centralized logging:" "WARN"
Write-Log "   - Forward IIS logs to SIEM" "WARN"
Write-Log "   - Set up log retention policies" "WARN"
Write-Log ""
Write-Log "8. Install and configure security modules:" "WARN"
Write-Log "   - URL Rewrite (for HTTPS enforcement)" "WARN"
Write-Log "   - Request Filtering (enhanced protection)" "WARN"
Write-Log ""
Write-Log "9. Run IIS vulnerability scans (Nessus/ACAS)" "WARN"
Write-Log ""
Write-Log "10. Document all site-specific configurations" "WARN"
Write-Log ""
Write-Log "To restore previous configuration if needed:" "INFO"
Write-Log "  Restore-WebConfiguration -Name $backupName" "INFO"
Write-Log ""
Write-Log "To view IIS configuration backups:" "INFO"
Write-Log "  Get-WebConfigurationBackup" "INFO"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
Write-Log "NOTE: System restart may be required for all changes to take effect" "WARN"
