$ErrorActionPreference = "Stop"

function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "ERROR: Please run script as Administrator."
        exit 1
    }
}

function Get-LocalIPv4 {
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                 Sort-Object -Property RouteMetric, InterfaceMetric |
                 Select-Object -First 1

        $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
              Where-Object { $_.IPAddress -notlike "169.254.*" } |
              Select-Object -First 1 -ExpandProperty IPAddress

        if ($ip) { return $ip }
    } catch { }

    $fallback = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -First 1 -ExpandProperty IPAddress

    return $fallback
}

Require-Admin

# Base directory = folder containing this setup.ps1 (like Linux/setup.sh)
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# -------------------------------
# Run Shared Scripts
# -------------------------------
Write-Host "Starting SSHD Script"
& (Join-Path $BaseDir "Shared\sshd\setupSSHD.ps1")
Write-Host "SSHD Script Handed Control to Setup"

Write-Host "Shared Scripts Done."
Write-Host "Starting Machine-Specific Scripts."

# -------------------------------
# Determine Machine for machine-specific scripts
# -------------------------------
$MACHINE_IP = Get-LocalIPv4

if (-not $MACHINE_IP) {
    Write-Error "ERROR: Could not determine local IPv4."
    exit 1
}

# -------------------------------
# Machine-Specific Logic
# -------------------------------
if ($MACHINE_IP -eq "172.20.240.102") {
    Write-Host "Machine Detected: Win19-AD"
    & (Join-Path $BaseDir "WindowsAD\hardening.ps1")
    & (Join-Path $BaseDir "")

} elseif ($MACHINE_IP -eq "172.20.240.101") {
    Write-Host "Machine Detected: Win22-Web"
    & (Join-Path $BaseDir "WindowsWeb\hardening.ps1")

} elseif ($MACHINE_IP -eq "172.20.240.104") {
    Write-Host "Machine Detected: Win22-FTP"
    & (Join-Path $BaseDir "WindowsFTP\hardening.ps1")

} elseif ($MACHINE_IP -eq "172.20.240.100") {
    Write-Host "Machine Detected: Win11-Wkst"
    & (Join-Path $BaseDir "WindowsWorkstation\hardening.ps1")

} else {

    Write-Error "ERROR: Machine not automatically identified."
    Write-Error "Please manually run machine-specific scripts!"
    exit 1
}

# -------------------------------
# Run Audit
# -------------------------------
Write-Host "Starting Audit"
& (Join-Path $BaseDir "Shared\audit.ps1")

Write-Host "Main Script Exiting..."
exit 0
