# OpenVAS/GVM Client Installation for Windows
# Installs Greenbone Security Assistant (GSA) via Docker Desktop
# Alternative: Connect to remote GVM server on Linux
# For Windows hosts in CCDC environment
# Version: 1.0
# Date: January 30, 2026

param(
    [string]$Mode = "Client",  # Client (connect to remote) or Docker (local container)
    [string]$RemoteGVMServer = "172.20.242.20",
    [string]$RemoteGVMPort = "9392",
    [switch]$InstallDocker
)

$ErrorActionPreference = "Stop"
$LogDir = "C:\Logs\OpenVAS"
$LogFile = "$LogDir\install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Create log directory
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage }
    }
}

Write-Log INFO "========================================"
Write-Log INFO "OpenVAS/GVM Windows Setup"
Write-Log INFO "Mode: $Mode"
Write-Log INFO "========================================"

# Check for admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log ERROR "This script requires administrator privileges"
    exit 1
}

if ($Mode -eq "Client") {
    Write-Log INFO "========================================"
    Write-Log INFO "GVM Client Mode - Remote Connection"
    Write-Log INFO "========================================"
    
    # Test connectivity to remote GVM server
    Write-Log INFO "Testing connection to GVM server: $RemoteGVMServer`:$RemoteGVMPort"
    
    try {
        $connection = Test-NetConnection -ComputerName $RemoteGVMServer -Port $RemoteGVMPort -WarningAction SilentlyContinue
        if ($connection.TcpTestSucceeded) {
            Write-Log SUCCESS "Successfully connected to GVM server"
        } else {
            Write-Log ERROR "Cannot reach GVM server at $RemoteGVMServer`:$RemoteGVMPort"
            Write-Log WARN "Make sure the GVM server is running and firewall allows port $RemoteGVMPort"
            exit 1
        }
    } catch {
        Write-Log ERROR "Connection test failed: $_"
        exit 1
    }
    
    # Create desktop shortcut to GVM web interface
    Write-Log INFO "Creating desktop shortcut..."
    
    $gvmUrl = "https://$RemoteGVMServer`:$RemoteGVMPort"
    $shortcutPath = "$env:USERPROFILE\Desktop\OpenVAS-GVM.url"
    
    $shortcutContent = @"
[InternetShortcut]
URL=$gvmUrl
IconIndex=0
IconFile=C:\Windows\System32\SHELL32.dll
"@
    
    Set-Content -Path $shortcutPath -Value $shortcutContent
    Write-Log SUCCESS "Desktop shortcut created: OpenVAS-GVM.url"
    
    # Install Python and gvm-tools for CLI access (optional)
    Write-Log INFO "Installing Python and gvm-tools for command-line access..."
    
    try {
        # Check if Python is installed
        $pythonInstalled = Get-Command python -ErrorAction SilentlyContinue
        
        if (-not $pythonInstalled) {
            Write-Log WARN "Python not found. Installing Python 3..."
            
            $pythonUrl = "https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"
            $pythonInstaller = "$env:TEMP\python-installer.exe"
            
            Write-Log INFO "Downloading Python..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
            
            Write-Log INFO "Installing Python (this may take a few minutes)..."
            Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
            
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            Write-Log SUCCESS "Python installed"
            Remove-Item $pythonInstaller -Force
        } else {
            Write-Log INFO "Python is already installed"
        }
        
        # Install gvm-tools
        Write-Log INFO "Installing gvm-tools via pip..."
        & python -m pip install --upgrade pip
        & python -m pip install gvm-tools python-gvm
        
        Write-Log SUCCESS "gvm-tools installed"
        
    } catch {
        Write-Log WARN "Failed to install Python/gvm-tools: $_"
        Write-Log WARN "CLI access will not be available, but web interface works"
    }
    
    # Create connection script
    Write-Log INFO "Creating GVM connection scripts..."
    
    $connectScript = @"
# GVM Connection Script
# Connect to remote GVM server for vulnerability scanning

`$GVMServer = "$RemoteGVMServer"
`$GVMPort = "$RemoteGVMPort"
`$GVMUrl = "https://`$GVMServer`:$GVMPort"

Write-Host "========================================"
Write-Host "OpenVAS/GVM Remote Connection"
Write-Host "========================================"
Write-Host "GVM Server: `$GVMServer"
Write-Host "Web Interface: `$GVMUrl"
Write-Host ""
Write-Host "Opening web browser..."

Start-Process "`$GVMUrl"

Write-Host ""
Write-Host "Default Credentials:"
Write-Host "  Username: admin"
Write-Host "  Password: (check /root/gvm-admin-password.txt on server)"
Write-Host ""
Write-Host "CLI Access (if gvm-tools installed):"
Write-Host "  gvm-cli socket --socketpath /var/run/gvmd/gvmd.sock --xml '<get_version/>'"
Write-Host "  gvm-cli --gmp-username admin --gmp-password PASSWORD socket --xml '<get_tasks/>'"
Write-Host ""
"@
    
    $connectScriptPath = "$env:USERPROFILE\Desktop\Connect-GVM.ps1"
    Set-Content -Path $connectScriptPath -Value $connectScript
    Write-Log SUCCESS "Connection script created: Connect-GVM.ps1"
    
    # Create scan targets documentation
    $targetsDoc = @"
# CCDC 2026 OpenVAS/GVM Scan Targets

## Network Segments
- Windows Network: 172.20.240.0/24
- Linux Network: 172.20.242.0/24
- Router Network: 172.16.101.0/24

## Windows Hosts
- Windows 11 Workstation: 172.20.240.100
- Server 2019 Web: 172.20.240.101
- Server 2019 AD/DNS: 172.20.240.102
- Server 2022 FTP: 172.20.240.104

## Linux Hosts
- Splunk Oracle Linux: 172.20.242.20
- Ubuntu Ecom Server: 172.20.242.30
- Mailserver Fedora: 172.20.242.40
- Ubuntu Desktop: 172.20.242.50

## Network Devices
- Cisco FTD: 172.20.240.200
- Palo Alto: 172.20.242.150
- VyOS Router: 172.16.101.1

## Scan Workflow
1. Access GVM: https://$RemoteGVMServer`:$RemoteGVMPort
2. Navigate to: Configuration → Targets → New Target
3. Create target with CCDC networks
4. Navigate to: Scans → Tasks → New Task
5. Select "Full and Fast" scan configuration
6. Start scan and monitor progress
7. View results: Scans → Reports

## Scan Recommendations
- Run initial baseline scan before CCDC competition
- Perform full network scan: 172.20.240.0/23 (covers both networks)
- Individual host scans for detailed analysis
- Prioritize critical systems: AD/DNS, Web servers, network devices
- Re-scan after applying STIG configurations to verify improvements
"@
    
    $targetsDocPath = "$env:USERPROFILE\Desktop\GVM-CCDC-Targets.txt"
    Set-Content -Path $targetsDocPath -Value $targetsDoc
    Write-Log SUCCESS "Scan targets documentation created: GVM-CCDC-Targets.txt"
    
    Write-Log INFO ""
    Write-Log INFO "========================================"
    Write-Log INFO "GVM Client Setup Complete"
    Write-Log INFO "========================================"
    Write-Log SUCCESS "GVM Server: https://$RemoteGVMServer`:$RemoteGVMPort"
    Write-Log INFO ""
    Write-Log INFO "Desktop Files Created:"
    Write-Log INFO "  - OpenVAS-GVM.url (click to open web interface)"
    Write-Log INFO "  - Connect-GVM.ps1 (connection script)"
    Write-Log INFO "  - GVM-CCDC-Targets.txt (scan targets list)"
    Write-Log INFO ""
    Write-Log INFO "Next Steps:"
    Write-Log INFO "1. Double-click OpenVAS-GVM.url on desktop"
    Write-Log INFO "2. Accept SSL certificate warning (self-signed)"
    Write-Log INFO "3. Log in with admin credentials"
    Write-Log INFO "4. Create scan targets using GVM-CCDC-Targets.txt"
    Write-Log INFO "5. Run vulnerability scans"
    Write-Log INFO ""
    Write-Log WARN "Note: Get admin password from Linux server:"
    Write-Log WARN "  SSH to $RemoteGVMServer"
    Write-Log WARN "  Run: cat /root/gvm-admin-password.txt"
    
} elseif ($Mode -eq "Docker" -or $InstallDocker) {
    Write-Log INFO "========================================"
    Write-Log INFO "GVM Docker Mode - Local Installation"
    Write-Log INFO "========================================"
    Write-Log WARN "This will install Docker Desktop and run GVM container"
    Write-Log WARN "Requires 8GB+ RAM and 20GB+ disk space"
    
    # Check if Docker is installed
    $dockerInstalled = Get-Command docker -ErrorAction SilentlyContinue
    
    if (-not $dockerInstalled) {
        Write-Log INFO "Docker not found. Installing Docker Desktop..."
        
        $dockerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
        $dockerInstaller = "$env:TEMP\DockerDesktopInstaller.exe"
        
        try {
            Write-Log INFO "Downloading Docker Desktop (this may take several minutes)..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $dockerUrl -OutFile $dockerInstaller -UseBasicParsing
            
            Write-Log INFO "Installing Docker Desktop..."
            Start-Process -FilePath $dockerInstaller -ArgumentList "install", "--quiet" -Wait
            
            Write-Log SUCCESS "Docker Desktop installed"
            Write-Log WARN "You must restart your computer before continuing"
            Write-Log WARN "After restart, run this script again with -Mode Docker"
            
            Remove-Item $dockerInstaller -Force
            exit 0
            
        } catch {
            Write-Log ERROR "Failed to install Docker Desktop: $_"
            Write-Log INFO "Please install Docker Desktop manually from: https://www.docker.com/products/docker-desktop"
            exit 1
        }
    }
    
    # Wait for Docker to start
    Write-Log INFO "Checking Docker status..."
    $dockerRunning = $false
    $retries = 0
    while (-not $dockerRunning -and $retries -lt 30) {
        try {
            docker ps | Out-Null
            $dockerRunning = $true
        } catch {
            Write-Log WARN "Waiting for Docker to start... ($retries/30)"
            Start-Sleep -Seconds 2
            $retries++
        }
    }
    
    if (-not $dockerRunning) {
        Write-Log ERROR "Docker is not running. Please start Docker Desktop and try again."
        exit 1
    }
    
    Write-Log SUCCESS "Docker is running"
    
    # Pull and run Greenbone Community Container
    Write-Log INFO "Pulling Greenbone Community Container (this may take 10-20 minutes)..."
    
    try {
        docker pull greenbone/openvas-scanner:stable
        docker pull greenbone/gvmd:stable
        docker pull greenbone/gsad:stable
        docker pull greenbone/ospd-openvas:stable
        
        Write-Log SUCCESS "GVM containers downloaded"
        
        # Create docker-compose file for GVM
        $dockerCompose = @"
version: '3'

services:
  gvmd:
    image: greenbone/gvmd:stable
    ports:
      - "9390:9390"
    volumes:
      - gvmd_data:/var/lib/gvm
    environment:
      - GVMD_POSTGRESQL_URI=postgresql://gvm:gvm@postgres:5432/gvmd
    depends_on:
      - postgres
    restart: unless-stopped

  gsad:
    image: greenbone/gsad:stable
    ports:
      - "9392:80"
      - "9393:443"
    volumes:
      - gsad_data:/var/lib/gvm
    depends_on:
      - gvmd
    restart: unless-stopped

  openvas:
    image: greenbone/openvas-scanner:stable
    volumes:
      - openvas_data:/var/lib/openvas
    environment:
      - REDIS_SERVER=redis
    depends_on:
      - redis
    restart: unless-stopped

  ospd:
    image: greenbone/ospd-openvas:stable
    volumes:
      - ospd_data:/var/lib/openvas
    depends_on:
      - openvas
    restart: unless-stopped

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=gvmd
      - POSTGRES_USER=gvm
      - POSTGRES_PASSWORD=gvm
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  gvmd_data:
  gsad_data:
  openvas_data:
  ospd_data:
  postgres_data:
  redis_data:
"@
        
        $dockerComposePath = "$env:USERPROFILE\gvm-docker-compose.yml"
        Set-Content -Path $dockerComposePath -Value $dockerCompose
        
        Write-Log INFO "Starting GVM containers..."
        Set-Location $env:USERPROFILE
        docker-compose -f gvm-docker-compose.yml up -d
        
        Write-Log SUCCESS "GVM containers started"
        Write-Log INFO "Waiting for services to initialize (30 seconds)..."
        Start-Sleep -Seconds 30
        
        Write-Log INFO ""
        Write-Log INFO "========================================"
        Write-Log INFO "GVM Docker Installation Complete"
        Write-Log INFO "========================================"
        Write-Log INFO "Web Interface: https://localhost:9392"
        Write-Log INFO "Username: admin"
        Write-Log INFO "Password: admin (change on first login)"
        Write-Log INFO ""
        Write-Log INFO "Docker Management:"
        Write-Log INFO "  View logs: docker-compose -f $dockerComposePath logs"
        Write-Log INFO "  Stop GVM: docker-compose -f $dockerComposePath stop"
        Write-Log INFO "  Start GVM: docker-compose -f $dockerComposePath start"
        Write-Log INFO "  Remove GVM: docker-compose -f $dockerComposePath down"
        Write-Log INFO ""
        Write-Log WARN "Note: First feed sync takes 30-60 minutes"
        Write-Log WARN "Web interface may be slow until feeds complete"
        
        # Open browser
        Start-Sleep -Seconds 5
        Start-Process "https://localhost:9392"
        
    } catch {
        Write-Log ERROR "Failed to start GVM containers: $_"
        Write-Log INFO "Try running Docker Desktop manually and checking for errors"
        exit 1
    }
    
} else {
    Write-Log ERROR "Invalid mode: $Mode"
    Write-Log INFO "Usage: .\Install-OpenVAS-Windows.ps1 -Mode [Client|Docker]"
    Write-Log INFO "  Client: Connect to remote GVM server (recommended for CCDC)"
    Write-Log INFO "  Docker: Install local GVM using Docker Desktop (resource intensive)"
    exit 1
}

Write-Log INFO ""
Write-Log SUCCESS "Setup complete! Log file: $LogFile"
