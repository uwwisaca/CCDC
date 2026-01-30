# PowerShell Script to Apply Apache 2.4 Windows Site STIG
# Based on: U_Apache_Server_2-4_Windows_Site_V2R2_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# This script configures site-specific Apache security settings
# Run AFTER Apply-Apache-Windows-Server-STIG.ps1
#
# Usage: Run as Administrator
# .\Apply-Apache-Windows-Site-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\Apache-Site-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\Logs\Apache-Site-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Apache 2.4 Windows Site STIG Application Starting"
Write-Log "========================================"

# Detect Apache installation
$ApachePaths = @(
    "C:\Apache24",
    "C:\Program Files\Apache Software Foundation\Apache2.4",
    "C:\Apache",
    "C:\xampp\apache"
)

$ApacheHome = $null
foreach ($path in $ApachePaths) {
    if (Test-Path "$path\conf\httpd.conf") {
        $ApacheHome = $path
        break
    }
}

if (-not $ApacheHome) {
    Write-Log "Apache installation not found" "ERROR"
    exit 1
}

Write-Log "Apache installation: $ApacheHome" "SUCCESS"

$ConfDir = "$ApacheHome\conf"
$ExtraDir = "$ConfDir\extra"
$VhostDir = "$ConfDir\vhosts"

# Create backup
New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
Copy-Item -Path $ConfDir -Destination "$BackupDir\conf" -Recurse -Force
Write-Log "Backup created: $BackupDir" "SUCCESS"

# Create vhosts directory
if (!(Test-Path $VhostDir)) {
    New-Item -Path $VhostDir -ItemType Directory -Force | Out-Null
}

# ========================================
# Create Site-Specific Configuration
# ========================================

Write-Log "Creating site-specific STIG configuration..." "INFO"

$siteSecurityConf = @"
# Apache 2.4 Windows Site STIG Configuration
# Site-specific security settings

# AS24-W1-000210: Session management
<IfModule mod_session.c>
    Session On
    SessionMaxAge 900
    SessionCookieName session path=/
    SessionCryptoPassphrase "ChangeThisToASecureRandomString"
</IfModule>

# AS24-W1-000220: Cookie security
<IfModule mod_headers.c>
    Header edit Set-Cookie ^(.*)$ `$1;HttpOnly;Secure;SameSite=Strict
</IfModule>

# AS24-W1-000230: Content Security Policy
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self';"
</IfModule>

# AS24-W1-000240: Referrer Policy
<IfModule mod_headers.c>
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# AS24-W1-000250: Permissions Policy
<IfModule mod_headers.c>
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# AS24-W1-000260: File upload restrictions
<Directory "C:/Apache24/htdocs/uploads">
    Options -ExecCGI -Indexes
    AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
    RemoveHandler .php .pl .py .jsp .asp .sh .cgi
    
    <FilesMatch "\.(exe|dll|bat|cmd|com|pif|scr|vbs|js|msi|jar)$">
        Require all denied
    </FilesMatch>
</Directory>

# AS24-W1-000270: Protect sensitive directories
<DirectoryMatch "^/.*/\.(svn|git|hg|bzr|cvs)">
    Require all denied
</DirectoryMatch>

<DirectoryMatch "^/.*/\.(config|env|bak|backup|swp|old|temp|tmp)$">
    Require all denied
</DirectoryMatch>

# AS24-W1-000280: Disable server-side includes
<Directory "C:/Apache24/htdocs">
    Options -Includes -ExecCGI
</Directory>

# AS24-W1-000290: Access logging for all sites
<IfModule mod_log_config.c>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{Host}i %D" vhost_combined
</IfModule>

# AS24-W1-000300: Error document customization
ErrorDocument 400 /errors/400.html
ErrorDocument 401 /errors/401.html
ErrorDocument 403 /errors/403.html
ErrorDocument 404 /errors/404.html
ErrorDocument 500 /errors/500.html
ErrorDocument 502 /errors/502.html
ErrorDocument 503 /errors/503.html

# AS24-W1-000310: Disable ETags
FileETag None

# AS24-W1-000320: MIME type security
<IfModule mod_mime.c>
    AddType application/x-httpd-php .php
    AddType application/x-httpd-php-source .phps
    
    # Prevent MIME sniffing
    <IfModule mod_headers.c>
        Header set X-Content-Type-Options "nosniff"
    </IfModule>
</IfModule>

"@

$siteSecurityConf | Out-File -FilePath "$ExtraDir\httpd-site-security.conf" -Encoding UTF8
Write-Log "Created site security configuration" "SUCCESS"

# ========================================
# Create Virtual Host Template
# ========================================

Write-Log "Creating virtual host template..." "INFO"

$vhostTemplate = @"
# Virtual Host Configuration Template (STIG Compliant)
# Copy and customize this template for each website

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    ServerAdmin webmaster@example.com
    
    DocumentRoot "C:/Apache24/htdocs/example.com"
    
    # Redirect all HTTP to HTTPS
    Redirect permanent / https://example.com/
    
    # Logging
    ErrorLog "logs/example.com-error.log"
    CustomLog "logs/example.com-access.log" vhost_combined
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    ServerAdmin webmaster@example.com
    
    DocumentRoot "C:/Apache24/htdocs/example.com"
    
    # SSL Configuration
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    SSLHonorCipherOrder on
    
    SSLCertificateFile "conf/ssl/example.com.crt"
    SSLCertificateKeyFile "conf/ssl/example.com.key"
    SSLCertificateChainFile "conf/ssl/example.com-chain.crt"
    
    # HSTS Header
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Directory Configuration
    <Directory "C:/Apache24/htdocs/example.com">
        Options -Indexes -FollowSymLinks -ExecCGI
        AllowOverride None
        Require all granted
        
        # Additional security
        <LimitExcept GET POST HEAD>
            Require all denied
        </LimitExcept>
    </Directory>
    
    # Restrict access to .ht files
    <FilesMatch "^\.ht">
        Require all denied
    </FilesMatch>
    
    # Block access to sensitive files
    <FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$">
        Require all denied
    </FilesMatch>
    
    # Logging
    ErrorLog "logs/example.com-ssl-error.log"
    CustomLog "logs/example.com-ssl-access.log" vhost_combined
    
    # Disable TRACE
    TraceEnable Off
</VirtualHost>

"@

$vhostTemplate | Out-File -FilePath "$VhostDir\example.com.conf.template" -Encoding UTF8
Write-Log "Created virtual host template: $VhostDir\example.com.conf.template" "SUCCESS"

# ========================================
# Create Error Pages
# ========================================

Write-Log "Creating custom error pages..." "INFO"

$errorDir = "$ApacheHome\htdocs\errors"
if (!(Test-Path $errorDir)) {
    New-Item -Path $errorDir -ItemType Directory -Force | Out-Null
}

$errorPages = @{
    "400" = "Bad Request"
    "401" = "Unauthorized"
    "403" = "Forbidden"
    "404" = "Not Found"
    "500" = "Internal Server Error"
    "502" = "Bad Gateway"
    "503" = "Service Unavailable"
}

foreach ($code in $errorPages.Keys) {
    $errorHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error $code - $($errorPages[$code])</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        p { color: #666; }
    </style>
</head>
<body>
    <h1>Error $code</h1>
    <p>$($errorPages[$code])</p>
    <p>Please contact the administrator if you believe this is an error.</p>
</body>
</html>
"@
    
    $errorHtml | Out-File -FilePath "$errorDir\$code.html" -Encoding UTF8
}

Write-Log "Created custom error pages in: $errorDir" "SUCCESS"

# ========================================
# Update httpd.conf to Include Site Configuration
# ========================================

Write-Log "Updating httpd.conf to include site configuration..." "INFO"

$HttpdConf = "$ConfDir\httpd.conf"
$httpdContent = Get-Content $HttpdConf -Raw

if ($httpdContent -notmatch "httpd-site-security.conf") {
    $siteInclude = @"

# Site-specific STIG configuration
Include conf/extra/httpd-site-security.conf

# Virtual host configurations
# Uncomment to enable virtual host configurations
# IncludeOptional conf/vhosts/*.conf

"@
    
    Add-Content -Path $HttpdConf -Value $siteInclude
    Write-Log "Added site configuration include to httpd.conf" "SUCCESS"
}

# ========================================
# Configure Log Rotation
# ========================================

Write-Log "Creating log rotation script..." "INFO"

$logRotateScript = @"
# Apache Log Rotation Script
# Schedule this script to run weekly via Task Scheduler

`$LogDir = "$ApacheHome\logs"
`$ArchiveDir = "$ApacheHome\logs\archive"

if (!(Test-Path `$ArchiveDir)) {
    New-Item -Path `$ArchiveDir -ItemType Directory -Force | Out-Null
}

`$Date = Get-Date -Format "yyyyMMdd"

# Get Apache service
`$ApacheService = Get-Service -Name "Apache2.4" -ErrorAction SilentlyContinue

if (`$ApacheService -and `$ApacheService.Status -eq "Running") {
    # Stop Apache
    Stop-Service -Name "Apache2.4"
    Start-Sleep -Seconds 2
    
    # Rotate logs
    Get-ChildItem -Path `$LogDir -Filter "*.log" | ForEach-Object {
        `$ArchiveName = `$_.BaseName + "-`$Date" + `$_.Extension
        Move-Item -Path `$_.FullName -Destination "`$ArchiveDir\`$ArchiveName" -Force
    }
    
    # Start Apache
    Start-Service -Name "Apache2.4"
    
    # Compress old logs (older than 7 days)
    Get-ChildItem -Path `$ArchiveDir -Filter "*.log" | Where-Object {
        `$_.LastWriteTime -lt (Get-Date).AddDays(-7)
    } | ForEach-Object {
        Compress-Archive -Path `$_.FullName -DestinationPath "`$(`$_.FullName).zip" -Force
        Remove-Item -Path `$_.FullName -Force
    }
    
    # Delete compressed logs older than 52 days
    Get-ChildItem -Path `$ArchiveDir -Filter "*.zip" | Where-Object {
        `$_.LastWriteTime -lt (Get-Date).AddDays(-52)
    } | Remove-Item -Force
}
"@

$logRotateScript | Out-File -FilePath "$ApacheHome\bin\Rotate-Logs.ps1" -Encoding UTF8
Write-Log "Created log rotation script: $ApacheHome\bin\Rotate-Logs.ps1" "SUCCESS"

# ========================================
# Test Configuration
# ========================================

Write-Log "Testing Apache configuration..." "INFO"

$httpdExe = "$ApacheHome\bin\httpd.exe"
if (Test-Path $httpdExe) {
    $testResult = & $httpdExe -t 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Apache configuration test passed" "SUCCESS"
    }
    else {
        Write-Log "Apache configuration test failed:" "ERROR"
        Write-Log $testResult "ERROR"
    }
}

Write-Log ""
Write-Log "========================================"
Write-Log "Apache Windows Site STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Backup: $BackupDir"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log ""
Write-Log "1. Create virtual host configurations:" "WARN"
Write-Log "   - Copy template: $VhostDir\example.com.conf.template" "WARN"
Write-Log "   - Customize for each website" "WARN"
Write-Log "   - Enable in httpd.conf: IncludeOptional conf/vhosts/*.conf" "WARN"
Write-Log ""
Write-Log "2. Configure SSL certificates for each virtual host" "WARN"
Write-Log "   - Obtain CA-signed certificates" "WARN"
Write-Log "   - Place in conf/ssl/ directory" "WARN"
Write-Log "   - Update SSLCertificateFile paths in vhost configs" "WARN"
Write-Log ""
Write-Log "3. Create website directories:" "WARN"
Write-Log "   - C:\Apache24\htdocs\yourdomain.com" "WARN"
Write-Log "   - Set appropriate file permissions" "WARN"
Write-Log ""
Write-Log "4. Schedule log rotation:" "WARN"
Write-Log "   - Open Task Scheduler" "WARN"
Write-Log "   - Create new task: Run weekly" "WARN"
Write-Log "   - Action: PowerShell.exe -File '$ApacheHome\bin\Rotate-Logs.ps1'" "WARN"
Write-Log ""
Write-Log "5. Customize Content Security Policy for your application" "WARN"
Write-Log "   - Edit: $ExtraDir\httpd-site-security.conf" "WARN"
Write-Log "   - Adjust CSP directives based on requirements" "WARN"
Write-Log ""
Write-Log "6. Test each virtual host:" "WARN"
Write-Log "   - HTTP redirect to HTTPS" "WARN"
Write-Log "   - SSL certificate validity" "WARN"
Write-Log "   - Application functionality" "WARN"
Write-Log "   - Security headers (use online tools)" "WARN"
Write-Log ""
Write-Log "7. Configure application-specific settings:" "WARN"
Write-Log "   - PHP settings (if using PHP)" "WARN"
Write-Log "   - Database connections" "WARN"
Write-Log "   - Session storage" "WARN"
Write-Log ""
Write-Log "8. Implement Web Application Firewall (ModSecurity recommended)" "WARN"
Write-Log ""
Write-Log "9. Set up monitoring and alerting:" "WARN"
Write-Log "   - Monitor error logs for issues" "WARN"
Write-Log "   - Alert on suspicious access patterns" "WARN"
Write-Log "   - Track performance metrics" "WARN"
Write-Log ""
Write-Log "10. Run security scan and penetration testing" "WARN"
Write-Log ""
Write-Log "Documentation:" "INFO"
Write-Log "  Virtual host template: $VhostDir\example.com.conf.template" "INFO"
Write-Log "  Site security config: $ExtraDir\httpd-site-security.conf" "INFO"
Write-Log "  Error pages: $errorDir\" "INFO"
Write-Log "  Log rotation script: $ApacheHome\bin\Rotate-Logs.ps1" "INFO"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
