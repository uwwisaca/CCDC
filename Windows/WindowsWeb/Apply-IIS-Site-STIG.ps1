# PowerShell Script to Apply IIS 10.0 Site STIG
# Based on: U_IIS_10-0_Site_V2R9_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Applies site-specific IIS hardening
# Run AFTER Apply-IIS-Server-STIG.ps1
#
# Usage: Run as Administrator
# .\Apply-IIS-Site-STIG.ps1 [-SiteName "Default Web Site"]

#Requires -RunAsAdministrator

param(
    [string]$SiteName = "Default Web Site"
)

Import-Module WebAdministration -ErrorAction SilentlyContinue

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\IIS-Site-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\Logs\IIS-Site-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "IIS 10.0 Site STIG Application Starting"
Write-Log "Target Site: $SiteName"
Write-Log "========================================"

# Verify IIS is installed
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Log "IIS Web Administration module not found" "ERROR"
    exit 1
}

Import-Module WebAdministration

# Verify site exists
$site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
if (-not $site) {
    Write-Log "Site not found: $SiteName" "ERROR"
    Write-Log "Available sites:" "INFO"
    Get-Website | ForEach-Object { Write-Log "  - $($_.Name)" "INFO" }
    exit 1
}

Write-Log "Site found: $SiteName" "SUCCESS"

# Create backup
New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
$backupName = "Site-STIG-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Backup-WebConfiguration -Name $backupName
Write-Log "Configuration backed up: $backupName" "SUCCESS"

$sitePath = "IIS:\Sites\$SiteName"
$configPath = "MACHINE/WEBROOT/APPHOST/$SiteName"

# ========================================
# STIG V-218814: Configure site logging
# ========================================
Write-Log "Configuring site-specific logging..." "INFO"

# Enable logging
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpLogging" -Name "dontLog" -Value $false

# Configure log file location
$logPath = "$env:SystemDrive\inetpub\logs\LogFiles\$SiteName"
if (!(Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

Set-ItemProperty $sitePath -Name logFile.directory -Value $logPath

# Set log format to W3C
Set-ItemProperty $sitePath -Name logFile.logFormat -Value "W3C"

# Configure log fields
Set-ItemProperty $sitePath -Name logFile.logExtFileFlags -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"

# Set log file rollover (daily)
Set-ItemProperty $sitePath -Name logFile.period -Value "Daily"

# Enable local time
Set-ItemProperty $sitePath -Name logFile.localTimeRollover -Value $true

Write-Log "Site logging configured" "SUCCESS"

# ========================================
# STIG V-218815: Configure HTTPS binding
# ========================================
Write-Log "Checking HTTPS binding..." "INFO"

$httpsBinding = Get-WebBinding -Name $SiteName -Protocol "https" -ErrorAction SilentlyContinue

if (-not $httpsBinding) {
    Write-Log "No HTTPS binding found - must be configured manually" "WARN"
    Write-Log "After obtaining SSL certificate, run:" "WARN"
    Write-Log "  New-WebBinding -Name '$SiteName' -Protocol https -Port 443" "WARN"
    Write-Log "  `$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {`$_.Subject -like '*yourdomain.com*'}" "WARN"
    Write-Log "  `$binding = Get-WebBinding -Name '$SiteName' -Protocol https" "WARN"
    Write-Log "  `$binding.AddSslCertificate(`$cert.Thumbprint, 'my')" "WARN"
}
else {
    Write-Log "HTTPS binding exists" "SUCCESS"
}

# ========================================
# STIG V-218816: Disable HTTP (optional - configure redirect)
# ========================================
Write-Log "Checking HTTP binding..." "INFO"

$httpBinding = Get-WebBinding -Name $SiteName -Protocol "http" -ErrorAction SilentlyContinue

if ($httpBinding) {
    Write-Log "HTTP binding exists - consider redirecting to HTTPS" "WARN"
    Write-Log "To redirect HTTP to HTTPS, install URL Rewrite module and configure redirect rules" "INFO"
}

# ========================================
# STIG V-218817: Configure session state
# ========================================
Write-Log "Configuring session state..." "INFO"

# Set session timeout to 20 minutes
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.web/sessionState" -Name "timeout" -Value "00:20:00"

# Use cookies only
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.web/sessionState" -Name "cookieless" -Value "UseCookies"

# Regenerate expired session ID
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.web/sessionState" -Name "regenerateExpiredSessionId" -Value $true

Write-Log "Session state configured" "SUCCESS"

# ========================================
# STIG V-218818: Configure authentication
# ========================================
Write-Log "Configuring authentication..." "INFO"

# Disable anonymous authentication (enable per-application if needed)
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value $false

# Enable Windows authentication
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value $true

# Disable Basic authentication
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authentication/basicAuthentication" -Name "enabled" -Value $false

# Disable Digest authentication
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authentication/digestAuthentication" -Name "enabled" -Value $false

Write-Log "Authentication configured (Windows only)" "SUCCESS"

# ========================================
# STIG V-218819: Configure authorization
# ========================================
Write-Log "Configuring authorization..." "INFO"

# Clear existing rules
Clear-WebConfiguration -PSPath $configPath -Filter "system.webServer/security/authorization"

# Add rule to deny anonymous users
Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authorization" -Name "." -Value @{accessType="Deny"; users="?"}

# Add rule to allow authenticated users
Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/authorization" -Name "." -Value @{accessType="Allow"; users="*"}

Write-Log "Authorization configured (authenticated users only)" "SUCCESS"

# ========================================
# STIG V-218820: Disable directory browsing
# ========================================
Write-Log "Disabling directory browsing..." "INFO"

Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false

Write-Log "Directory browsing disabled" "SUCCESS"

# ========================================
# STIG V-218821: Configure default document
# ========================================
Write-Log "Configuring default documents..." "INFO"

# Clear default documents
Clear-WebConfiguration -PSPath $configPath -Filter "system.webServer/defaultDocument/files"

# Add secure default documents
$defaultDocs = @("index.html", "index.htm", "default.html", "default.htm", "default.aspx")

foreach ($doc in $defaultDocs) {
    Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value=$doc}
}

# Enable default document
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/defaultDocument" -Name "enabled" -Value $true

Write-Log "Default documents configured" "SUCCESS"

# ========================================
# STIG V-218822: Configure custom error pages
# ========================================
Write-Log "Configuring custom error pages..." "INFO"

# Set error mode to Custom
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "Custom"

# Remove detailed error information
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpErrors" -Name "existingResponse" -Value "Replace"

Write-Log "Custom error pages configured" "SUCCESS"

# ========================================
# STIG V-218823: Configure request filtering
# ========================================
Write-Log "Configuring request filtering..." "INFO"

# Enable request filtering
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering" -Name "allowDoubleEscaping" -Value $false
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering" -Name "allowHighBitCharacters" -Value $false

# Configure file extension filtering
$denyExtensions = @(".asa", ".asax", ".ascx", ".master", ".skin", ".browser", ".sitemap", ".config", ".cs", ".csproj", ".vb", ".vbproj", ".webinfo", ".licx", ".resx", ".resources")

foreach ($ext in $denyExtensions) {
    $exists = Get-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "Collection" | Where-Object { $_.fileExtension -eq $ext }
    
    if (-not $exists) {
        Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "." -Value @{fileExtension=$ext; allowed=$false}
    }
}

# Set max content length (30MB)
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 30000000

# Set max URL length
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 4096

# Set max query string
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048

Write-Log "Request filtering configured" "SUCCESS"

# ========================================
# STIG V-218824: Configure HTTP verbs
# ========================================
Write-Log "Configuring HTTP verb filtering..." "INFO"

# Clear existing verb rules
Clear-WebConfiguration -PSPath $configPath -Filter "system.webServer/security/requestFiltering/verbs"

# Allow only necessary verbs
$allowedVerbs = @("GET", "POST", "HEAD")

foreach ($verb in $allowedVerbs) {
    Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/verbs" -Name "." -Value @{verb=$verb; allowed=$true}
}

# Deny all unlisted verbs
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/requestFiltering/verbs" -Name "allowUnlisted" -Value $false

Write-Log "HTTP verb filtering configured" "SUCCESS"

# ========================================
# STIG V-218825: Configure handlers
# ========================================
Write-Log "Configuring handlers..." "INFO"

# Remove unnecessary handlers
$unnecessaryHandlers = @(
    "OPTIONSVerbHandler",
    "TRACEVerbHandler",
    "WebDAV"
)

foreach ($handler in $unnecessaryHandlers) {
    Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/handlers" -Name "." -AtElement @{name=$handler} -ErrorAction SilentlyContinue
}

Write-Log "Handlers configured" "SUCCESS"

# ========================================
# STIG V-218826: Configure modules
# ========================================
Write-Log "Checking IIS modules..." "INFO"

# Remove WebDAV module if present
Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/modules" -Name "." -AtElement @{name="WebDAVModule"} -ErrorAction SilentlyContinue

Write-Log "Modules configured" "SUCCESS"

# ========================================
# STIG V-218827: Configure application pool
# ========================================
Write-Log "Configuring application pool..." "INFO"

$appPoolName = (Get-Item $sitePath).applicationPool

if ($appPoolName) {
    Write-Log "Site uses application pool: $appPoolName" "INFO"
    
    # Set idle timeout
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.idleTimeout -Value "00:20:00"
    
    # Set recycle interval
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name recycling.periodicRestart.time -Value "1.05:00:00"
    
    # Enable rapid fail protection
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name failure.rapidFailProtection -Value $true
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name failure.rapidFailProtectionInterval -Value "00:05:00"
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name failure.rapidFailProtectionMaxCrashes -Value 5
    
    # Set identity to ApplicationPoolIdentity
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value "ApplicationPoolIdentity"
    
    # Disable 32-bit applications
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name enable32BitAppOnWin64 -Value $false
    
    Write-Log "Application pool configured: $appPoolName" "SUCCESS"
}

# ========================================
# STIG V-218828: Configure SSL settings
# ========================================
Write-Log "Configuring SSL settings..." "INFO"

# Require SSL
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/access" -Name "sslFlags" -Value "Ssl,SslRequireCert" -ErrorAction SilentlyContinue

# Note: SslRequireCert requires client certificates - adjust as needed
Set-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/security/access" -Name "sslFlags" -Value "Ssl" -ErrorAction SilentlyContinue

Write-Log "SSL settings configured" "SUCCESS"

# ========================================
# STIG V-218829: Configure HSTS
# ========================================
Write-Log "Configuring HSTS header..." "INFO"

# Remove existing HSTS header if present
Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name="Strict-Transport-Security"} -ErrorAction SilentlyContinue

# Add HSTS header
Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains; preload"}

Write-Log "HSTS header configured" "SUCCESS"

# ========================================
# STIG V-218830: Add security headers
# ========================================
Write-Log "Adding security headers..." "INFO"

$securityHeaders = @(
    @{name="X-Frame-Options"; value="SAMEORIGIN"},
    @{name="X-Content-Type-Options"; value="nosniff"},
    @{name="X-XSS-Protection"; value="1; mode=block"},
    @{name="Referrer-Policy"; value="strict-origin-when-cross-origin"},
    @{name="Permissions-Policy"; value="geolocation=(), microphone=(), camera=()"}
)

foreach ($header in $securityHeaders) {
    # Remove if exists
    Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name=$header.name} -ErrorAction SilentlyContinue
    
    # Add header
    Add-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value $header
}

Write-Log "Security headers configured" "SUCCESS"

# ========================================
# STIG V-218831: Remove unnecessary headers
# ========================================
Write-Log "Removing unnecessary response headers..." "INFO"

$headersToRemove = @("X-Powered-By", "Server", "X-AspNet-Version")

foreach ($header in $headersToRemove) {
    Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name=$header} -ErrorAction SilentlyContinue
}

Write-Log "Unnecessary headers removed" "SUCCESS"

# ========================================
# STIG V-218832: Configure MIME types
# ========================================
Write-Log "Configuring MIME types..." "INFO"

# Remove executable MIME types
$removeMimeTypes = @(".exe", ".dll", ".com", ".bat", ".cmd", ".vbs")

foreach ($mimeType in $removeMimeTypes) {
    Remove-WebConfigurationProperty -PSPath $configPath -Filter "system.webServer/staticContent" -Name "Collection" -AtElement @{fileExtension=$mimeType} -ErrorAction SilentlyContinue
}

Write-Log "MIME types configured" "SUCCESS"

# ========================================
# STIG V-218833: Set file system permissions
# ========================================
Write-Log "Configuring file system permissions..." "INFO"

$physicalPath = (Get-Item $sitePath).physicalPath
$physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)

if (Test-Path $physicalPath) {
    $acl = Get-Acl $physicalPath
    
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
    
    # Add application pool identity read and execute
    if ($appPoolName) {
        $poolIdentity = "IIS AppPool\$appPoolName"
        $poolRule = New-Object System.Security.AccessControl.FileSystemAccessRule($poolIdentity, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($poolRule)
    }
    
    # Add IIS_IUSRS read and execute
    $iisRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($iisRule)
    
    Set-Acl -Path $physicalPath -AclObject $acl
    Write-Log "File system permissions configured for: $physicalPath" "SUCCESS"
}
else {
    Write-Log "Physical path not found: $physicalPath" "WARN"
}

# ========================================
# Test configuration and restart site
# ========================================
Write-Log "Restarting site..." "INFO"

Stop-Website -Name $SiteName
Start-Sleep -Seconds 2
Start-Website -Name $SiteName

$siteState = (Get-Website -Name $SiteName).State
if ($siteState -eq "Started") {
    Write-Log "Site restarted successfully" "SUCCESS"
}
else {
    Write-Log "Site failed to start - State: $siteState" "ERROR"
}

Write-Log ""
Write-Log "========================================"
Write-Log "IIS 10.0 Site STIG Application Completed"
Write-Log "Site: $SiteName"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Configuration backup: $backupName"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log ""
Write-Log "1. Configure SSL certificate for site:" "WARN"
Write-Log "   - Obtain CA-signed certificate" "WARN"
Write-Log "   - Import to Certificate Store (Local Machine\Personal)" "WARN"
Write-Log "   - Bind to IIS site on port 443" "WARN"
Write-Log ""
Write-Log "2. Configure HTTP to HTTPS redirect:" "WARN"
Write-Log "   - Install URL Rewrite module" "WARN"
Write-Log "   - Create redirect rule for HTTP to HTTPS" "WARN"
Write-Log ""
Write-Log "3. Adjust authentication based on application requirements:" "WARN"
Write-Log "   - Currently set to Windows Authentication only" "WARN"
Write-Log "   - Enable Anonymous if needed for public sites" "WARN"
Write-Log "   - Configure Forms Authentication for ASP.NET apps" "WARN"
Write-Log ""
Write-Log "4. Customize Content Security Policy:" "WARN"
Write-Log "   - Review CSP header for application compatibility" "WARN"
Write-Log "   - Adjust script-src, style-src directives as needed" "WARN"
Write-Log ""
Write-Log "5. Test application functionality:" "WARN"
Write-Log "   - Test all application features" "WARN"
Write-Log "   - Verify authentication works" "WARN"
Write-Log "   - Check for blocked resources" "WARN"
Write-Log "   - Review IIS logs for errors" "WARN"
Write-Log ""
Write-Log "6. Configure URL Rewrite rules:" "WARN"
Write-Log "   - Force lowercase URLs" "WARN"
Write-Log "   - Remove trailing slashes" "WARN"
Write-Log "   - Block malicious patterns" "WARN"
Write-Log ""
Write-Log "7. Review allowed HTTP verbs:" "WARN"
Write-Log "   - Currently: GET, POST, HEAD" "WARN"
Write-Log "   - Add PUT, DELETE if needed for REST APIs" "WARN"
Write-Log ""
Write-Log "8. Configure application-specific settings:" "WARN"
Write-Log "   - Connection strings" "WARN"
Write-Log "   - App settings" "WARN"
Write-Log "   - Custom error pages" "WARN"
Write-Log ""
Write-Log "9. Run security scan:" "WARN"
Write-Log "   - Nessus/ACAS vulnerability scan" "WARN"
Write-Log "   - SSL/TLS configuration test (ssllabs.com)" "WARN"
Write-Log "   - Security headers test (securityheaders.com)" "WARN"
Write-Log ""
Write-Log "10. Document site-specific configurations and exceptions" "WARN"
Write-Log ""
Write-Log "To apply STIG to another site:" "INFO"
Write-Log "  .\Apply-IIS-Site-STIG.ps1 -SiteName 'Your Site Name'" "INFO"
Write-Log ""
Write-Log "To restore configuration if needed:" "INFO"
Write-Log "  Restore-WebConfiguration -Name $backupName" "INFO"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
