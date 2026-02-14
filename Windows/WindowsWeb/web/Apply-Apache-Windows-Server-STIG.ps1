# PowerShell Script to Apply Apache 2.4 Windows Server STIG
# Based on: U_Apache_Server_2-4_Windows_Server_V3R3_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: Run as Administrator
# .\Apply-Apache-Windows-Server-STIG.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$LogFile = "C:\Windows\Logs\Apache-Server-STIG-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BackupDir = "C:\Windows\Logs\Apache-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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
Write-Log "Apache 2.4 Windows Server STIG Application Starting"
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
    Write-Log "Apache installation not found in standard locations" "ERROR"
    Write-Log "Please specify Apache installation directory manually" "ERROR"
    exit 1
}

Write-Log "Apache installation found: $ApacheHome" "SUCCESS"

$ConfDir = "$ApacheHome\conf"
$HttpdConf = "$ConfDir\httpd.conf"
$ExtraDir = "$ConfDir\extra"

# Create backup
New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
Copy-Item -Path $ConfDir -Destination "$BackupDir\conf" -Recurse -Force
Write-Log "Backup created: $BackupDir" "SUCCESS"

# ========================================
# Create STIG Configuration Files
# ========================================

Write-Log "Creating STIG configuration files..." "INFO"

# Create extra directory if it doesn't exist
if (!(Test-Path $ExtraDir)) {
    New-Item -Path $ExtraDir -ItemType Directory -Force | Out-Null
}

# Create security configuration file
$securityConf = @"
# Apache 2.4 Windows Server STIG Configuration
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

# AS24-W1-000010: Server tokens (hide version info)
ServerTokens Prod
ServerSignature Off

# AS24-W1-000020: Disable TRACE method
TraceEnable Off

# AS24-W1-000030: Timeout settings
Timeout 10
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15

# AS24-W1-000040: Request limits
LimitRequestLine 8190
LimitRequestFieldSize 8190
LimitRequestFields 100
LimitRequestBody 1048576

# AS24-W1-000050: Security headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always unset X-Powered-By
    Header always unset Server
    Header edit Set-Cookie ^(.*)$ `$1;HttpOnly;Secure
</IfModule>

# AS24-W1-000060: Disable directory browsing
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

<Directory "C:/Apache24/htdocs">
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# AS24-W1-000070: Hide .ht files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# AS24-W1-000080: Restrict access to sensitive files
<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|bak~)$">
    Require all denied
</FilesMatch>

# AS24-W1-000090: Block executable uploads
<Directory "C:/Apache24/htdocs/uploads">
    <FilesMatch "\.(exe|dll|bat|cmd|com|pif|scr|vbs|js|msi)$">
        Require all denied
    </FilesMatch>
</Directory>

# AS24-W1-000100: Clickjacking protection
<IfModule mod_headers.c>
    Header always append X-Frame-Options SAMEORIGIN
</IfModule>

# AS24-W1-000110: Restrict HTTP methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# AS24-W1-000120: Log format
<IfModule mod_log_config.c>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_with_time
    CustomLog "logs/access.log" combined_with_time
    ErrorLog "logs/error.log"
</IfModule>

# AS24-W1-000130: Error log level
LogLevel warn

# AS24-W1-000140: Disable default content
RedirectMatch 404 /\..*$
Redirect 404 /icons
Redirect 404 /manual

"@

$securityConf | Out-File -FilePath "$ExtraDir\httpd-stig-security.conf" -Encoding UTF8
Write-Log "Created security configuration: $ExtraDir\httpd-stig-security.conf" "SUCCESS"

# Create SSL configuration
$sslConf = @"
# Apache 2.4 SSL/TLS STIG Configuration

<IfModule mod_ssl.c>
    # AS24-W2-000010: Enable SSL
    Listen 443
    
    <VirtualHost _default_:443>
        DocumentRoot "C:/Apache24/htdocs"
        ServerName localhost:443
        
        # AS24-W2-000020: SSL Engine
        SSLEngine on
        
        # AS24-W2-000030: SSL Protocols (TLS 1.2 and 1.3 only)
        SSLProtocol -all +TLSv1.2 +TLSv1.3
        
        # AS24-W2-000040: Strong cipher suites
        SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
        SSLHonorCipherOrder on
        
        # AS24-W2-000050: Disable SSL compression
        SSLCompression off
        
        # AS24-W2-000060: OCSP Stapling
        SSLUseStapling on
        SSLStaplingResponderTimeout 5
        SSLStaplingReturnResponderErrors off
        SSLStaplingCache "shmcb:logs/ssl_stapling(128000)"
        
        # AS24-W2-000070: Session cache
        SSLSessionCache "shmcb:logs/ssl_scache(512000)"
        SSLSessionCacheTimeout 300
        
        # AS24-W2-000080: Session tickets
        SSLSessionTickets off
        
        # AS24-W2-000090: Certificate files (update these paths)
        SSLCertificateFile "conf/ssl/server.crt"
        SSLCertificateKeyFile "conf/ssl/server.key"
        SSLCertificateChainFile "conf/ssl/ca-bundle.crt"
        
        # AS24-W2-000100: Client certificate verification (optional)
        # SSLVerifyClient require
        # SSLVerifyDepth 10
        # SSLCACertificateFile "conf/ssl/ca.crt"
        
        # AS24-W2-000110: HSTS header
        <IfModule mod_headers.c>
            Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        </IfModule>
        
        # Security headers for SSL site
        <IfModule mod_headers.c>
            Header always set X-Frame-Options "SAMEORIGIN"
            Header always set X-Content-Type-Options "nosniff"
            Header always set X-XSS-Protection "1; mode=block"
        </IfModule>
        
        <Directory "C:/Apache24/htdocs">
            Options -Indexes -FollowSymLinks
            AllowOverride None
            Require all granted
        </Directory>
        
        # Disable TRACE
        TraceEnable Off
        
        # Restrict HTTP methods
        <LimitExcept GET POST HEAD>
            Require all denied
        </LimitExcept>
        
        # Logging
        ErrorLog "logs/ssl_error.log"
        CustomLog "logs/ssl_access.log" combined_with_time
    </VirtualHost>
</IfModule>

"@

$sslConf | Out-File -FilePath "$ExtraDir\httpd-stig-ssl.conf" -Encoding UTF8
Write-Log "Created SSL configuration: $ExtraDir\httpd-stig-ssl.conf" "SUCCESS"

# ========================================
# Update main httpd.conf
# ========================================

Write-Log "Updating main httpd.conf..." "INFO"

# Read current httpd.conf
$httpdContent = Get-Content $HttpdConf -Raw

# Check if STIG configuration is already included
if ($httpdContent -notmatch "httpd-stig-security.conf") {
    $includeLines = @"

# STIG Security Configuration
Include conf/extra/httpd-stig-security.conf
Include conf/extra/httpd-stig-ssl.conf

"@
    
    Add-Content -Path $HttpdConf -Value $includeLines
    Write-Log "Added STIG configuration includes to httpd.conf" "SUCCESS"
}
else {
    Write-Log "STIG configuration already included in httpd.conf" "INFO"
}

# ========================================
# Enable Required Modules
# ========================================

Write-Log "Enabling required Apache modules..." "INFO"

$requiredModules = @(
    "mod_headers",
    "mod_ssl",
    "mod_log_config",
    "mod_socache_shmcb",
    "mod_rewrite"
)

foreach ($module in $requiredModules) {
    $moduleLine = "LoadModule $module"
    
    if ($httpdContent -match "#\s*$moduleLine") {
        # Uncomment the module
        $httpdContent = $httpdContent -replace "#\s*($moduleLine)", '$1'
        Write-Log "Enabled module: $module" "SUCCESS"
    }
    elseif ($httpdContent -match "$moduleLine") {
        Write-Log "Module already enabled: $module" "INFO"
    }
    else {
        Write-Log "Module not found in httpd.conf: $module" "WARN"
    }
}

# Save updated httpd.conf
$httpdContent | Out-File -FilePath $HttpdConf -Encoding UTF8

# ========================================
# Disable Unnecessary Modules
# ========================================

Write-Log "Disabling unnecessary modules..." "INFO"

$unnecessaryModules = @(
    "mod_autoindex",
    "mod_status",
    "mod_info",
    "mod_userdir",
    "mod_cgi"
)

$httpdContent = Get-Content $HttpdConf -Raw

foreach ($module in $unnecessaryModules) {
    $moduleLine = "LoadModule $module"
    
    if ($httpdContent -match "^\s*$moduleLine" -and $httpdContent -notmatch "^\s*#.*$moduleLine") {
        # Comment out the module
        $httpdContent = $httpdContent -replace "^(\s*)($moduleLine)", '$1#$2'
        Write-Log "Disabled module: $module" "SUCCESS"
    }
}

$httpdContent | Out-File -FilePath $HttpdConf -Encoding UTF8

# ========================================
# Create SSL Directory and Self-Signed Certificate
# ========================================

Write-Log "Setting up SSL certificates..." "INFO"

$sslDir = "$ConfDir\ssl"
if (!(Test-Path $sslDir)) {
    New-Item -Path $sslDir -ItemType Directory -Force | Out-Null
}

# Check if OpenSSL is available
$opensslPath = $null
$opensslPaths = @(
    "$ApacheHome\bin\openssl.exe",
    "C:\OpenSSL\bin\openssl.exe",
    "C:\Program Files\OpenSSL\bin\openssl.exe"
)

foreach ($path in $opensslPaths) {
    if (Test-Path $path) {
        $opensslPath = $path
        break
    }
}

if ($opensslPath) {
    Write-Log "Found OpenSSL: $opensslPath" "INFO"
    
    # Generate self-signed certificate (for testing - replace in production)
    $certPath = "$sslDir\server.crt"
    $keyPath = "$sslDir\server.key"
    
    if (!(Test-Path $certPath)) {
        Write-Log "Generating self-signed SSL certificate..." "WARN"
        
        & $opensslPath req -new -x509 -days 365 -nodes `
            -out $certPath `
            -keyout $keyPath `
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        if ($?) {
            Write-Log "Self-signed certificate created" "SUCCESS"
            Write-Log "Certificate: $certPath" "INFO"
            Write-Log "Private Key: $keyPath" "INFO"
            Write-Log "WARNING: Replace self-signed certificate with valid CA-signed certificate in production" "WARN"
        }
    }
    else {
        Write-Log "SSL certificate already exists: $certPath" "INFO"
    }
}
else {
    Write-Log "OpenSSL not found - SSL certificate must be created manually" "WARN"
}

# ========================================
# Set File Permissions
# ========================================

Write-Log "Setting file permissions..." "INFO"

# Set restrictive permissions on configuration directory
$acl = Get-Acl $ConfDir
$acl.SetAccessRuleProtection($true, $false)

# Remove all existing rules
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

# Add Administrators full control
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($adminRule)

# Add SYSTEM full control
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($systemRule)

# Add Apache service account read access (adjust username as needed)
# $apacheUser = "NT AUTHORITY\NETWORK SERVICE"
# $apacheRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
#     $apacheUser, "Read", "ContainerInherit,ObjectInherit", "None", "Allow"
# )
# $acl.AddAccessRule($apacheRule)

Set-Acl -Path $ConfDir -AclObject $acl
Write-Log "File permissions configured" "SUCCESS"

# ========================================
# Configure Windows Service
# ========================================

Write-Log "Configuring Apache Windows service..." "INFO"

$serviceName = "Apache2.4"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    Write-Log "Apache service found: $serviceName" "INFO"
    
    # Set service to automatic startup
    Set-Service -Name $serviceName -StartupType Automatic
    Write-Log "Service startup type set to Automatic" "SUCCESS"
}
else {
    Write-Log "Apache service not found: $serviceName" "WARN"
    Write-Log "Install service with: $ApacheHome\bin\httpd.exe -k install" "INFO"
}

# ========================================
# Test Configuration
# ========================================

Write-Log "Testing Apache configuration..." "INFO"

$httpdExe = "$ApacheHome\bin\httpd.exe"
if (Test-Path $httpdExe) {
    $testResult = & $httpdExe -t 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Apache configuration test passed" "SUCCESS"
        
        # Restart Apache service
        if ($service) {
            Write-Log "Restarting Apache service..." "INFO"
            Restart-Service -Name $serviceName -Force
            
            Start-Sleep -Seconds 3
            
            $serviceStatus = (Get-Service -Name $serviceName).Status
            if ($serviceStatus -eq "Running") {
                Write-Log "Apache service restarted successfully" "SUCCESS"
            }
            else {
                Write-Log "Apache service failed to start - Status: $serviceStatus" "ERROR"
            }
        }
    }
    else {
        Write-Log "Apache configuration test failed:" "ERROR"
        Write-Log $testResult "ERROR"
        Write-Log "Configuration errors must be fixed before starting Apache" "ERROR"
    }
}
else {
    Write-Log "Apache executable not found: $httpdExe" "ERROR"
}

# ========================================
# Configure Windows Firewall
# ========================================

Write-Log "Configuring Windows Firewall..." "INFO"

# Allow HTTP
$httpRule = Get-NetFirewallRule -DisplayName "Apache HTTP" -ErrorAction SilentlyContinue
if (!$httpRule) {
    New-NetFirewallRule -DisplayName "Apache HTTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 | Out-Null
    Write-Log "Firewall rule created for HTTP (port 80)" "SUCCESS"
}

# Allow HTTPS
$httpsRule = Get-NetFirewallRule -DisplayName "Apache HTTPS" -ErrorAction SilentlyContinue
if (!$httpsRule) {
    New-NetFirewallRule -DisplayName "Apache HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 | Out-Null
    Write-Log "Firewall rule created for HTTPS (port 443)" "SUCCESS"
}

Write-Log ""
Write-Log "========================================"
Write-Log "Apache Windows Server STIG Application Completed"
Write-Log "========================================"
Write-Log "Log file: $LogFile"
Write-Log "Backup: $BackupDir"
Write-Log "Apache Home: $ApacheHome"
Write-Log ""
Write-Log "=== CRITICAL NEXT STEPS ===" "WARN"
Write-Log "1. Replace self-signed SSL certificate with valid CA-signed certificate" "WARN"
Write-Log "   Certificate location: $sslDir\server.crt" "WARN"
Write-Log "   Private key location: $sslDir\server.key" "WARN"
Write-Log ""
Write-Log "2. Update SSL certificate paths in: $ExtraDir\httpd-stig-ssl.conf" "WARN"
Write-Log ""
Write-Log "3. Test Apache configuration:" "WARN"
Write-Log "   $ApacheHome\bin\httpd.exe -t" "WARN"
Write-Log ""
Write-Log "4. Configure virtual hosts for your applications" "WARN"
Write-Log ""
Write-Log "5. Review and customize security headers for your specific needs" "WARN"
Write-Log ""
Write-Log "6. Test all website functionality after STIG implementation" "WARN"
Write-Log ""
Write-Log "7. Configure WAF/ModSecurity if required (not included in base Apache)" "WARN"
Write-Log ""
Write-Log "8. Set up centralized logging to syslog or SIEM" "WARN"
Write-Log ""
Write-Log "9. Run vulnerability scan (Nessus/ACAS)" "WARN"
Write-Log ""
Write-Log "10. Review Apache access and error logs regularly:" "WARN"
Write-Log "    Access log: $ApacheHome\logs\access.log" "WARN"
Write-Log "    Error log: $ApacheHome\logs\error.log" "WARN"
Write-Log ""
Write-Log "To manually start/stop Apache service:" "INFO"
Write-Log "  Start:   net start Apache2.4" "INFO"
Write-Log "  Stop:    net stop Apache2.4" "INFO"
Write-Log "  Restart: net stop Apache2.4 && net start Apache2.4" "INFO"
Write-Log ""
Write-Log "Access Apache:" "INFO"
Write-Log "  HTTP:  http://localhost" "INFO"
Write-Log "  HTTPS: https://localhost" "INFO"
Write-Log ""
Write-Log "Script execution complete!" "SUCCESS"
