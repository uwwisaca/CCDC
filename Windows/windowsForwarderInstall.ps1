# PowerShell script: Production-ready Splunk Universal Forwarder installer
# Supports: Windows Server 2019, 2022, and Windows 11
# Automatically creates a non-interactive 'splunk' service user with a random password

# ----------------------------
# Configuration Variables
# ----------------------------
$SplunkURL = "https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi"
$InstallerPath = "$env:TEMP\splunkforwarder.msi"
$InstallDir = "C:\Program Files\SplunkUniversalForwarder"
$SplunkUser = "splunk"                      # Service user
$SplunkIndexer = "splunk.example.com:9997"  # Your Splunk indexer host:port
$ServiceName = "SplunkForwarder"

# ----------------------------
# Function: Generate a random strong password
# ----------------------------
function Generate-RandomPassword($length = 32) {
    Add-Type -AssemblyName System.Web
    $password = [System.Web.Security.Membership]::GeneratePassword($length, 8)
    return $password
}

# ----------------------------
# 1. Create the Splunk service user if it doesn't exist
# ----------------------------
if (-Not (Get-LocalUser -Name $SplunkUser -ErrorAction SilentlyContinue)) {
    Write-Host "Creating service user '$SplunkUser' with a random password..."
    $SplunkUserPassword = Generate-RandomPassword

    # Convert to secure string
    $SecurePass = ConvertTo-SecureString $SplunkUserPassword -AsPlainText -Force

    # Create user
    New-LocalUser -Name $SplunkUser -Password $SecurePass -FullName "Splunk Service User" -Description "Used to run Splunk Forwarder service" -PasswordNeverExpires

    # Deny interactive logon
    $UserSID = (Get-LocalUser -Name $SplunkUser).SID
    secedit /export /cfg $env:TEMP\secpol.cfg
    (Get-Content $env:TEMP\secpol.cfg) -replace 'SeDenyInteractiveLogonRight =','SeDenyInteractiveLogonRight = *S-1-5-21-' + $UserSID.Value | Set-Content $env:TEMP\secpol.cfg
    secedit /import /cfg $env:TEMP\secpol.cfg /quiet
    Remove-Item $env:TEMP\secpol.cfg

    # Add to Administrators group (optional, needed for Splunk service)
    Add-LocalGroupMember -Group "Administrators" -Member $SplunkUser

    Write-Host "Service user '$SplunkUser' created."
} else {
    Write-Host "Service user '$SplunkUser' already exists."
    $SplunkUserPassword = Read-Host "Enter password for existing splunk user" -AsSecureString
    $SplunkUserPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SplunkUserPassword))
}

# ----------------------------
# 2. Download the MSI if it doesn't exist
# ----------------------------
if (-Not (Test-Path $InstallerPath)) {
    Write-Host "Downloading Splunk Universal Forwarder..."
    Invoke-WebRequest -Uri $SplunkURL -OutFile $InstallerPath
} else {
    Write-Host "Installer already exists at $InstallerPath"
}

# ----------------------------
# 3. Install Splunk silently
# ----------------------------
Write-Host "Installing Splunk Universal Forwarder..."
Start-Process msiexec.exe -ArgumentList "/i `"$InstallerPath`" INSTALLDIR=`"$InstallDir`" AGREETOLICENSE=Yes /qn" -Wait

# Verify installation
if (-Not (Test-Path "$InstallDir\bin\splunk.exe")) {
    Write-Error "Splunk installation failed!"
    exit 1
} else {
    Write-Host "Splunk Universal Forwarder installed successfully."
}

# ----------------------------
# 4. Configure forward-server to the indexer
# ----------------------------
Write-Host "Configuring forward-server to Splunk Indexer: $SplunkIndexer"
& "$InstallDir\bin\splunk.exe" add forward-server $SplunkIndexer -auth admin:changeme

# ----------------------------
# 5. Set the Splunk service to run as the 'splunk' user
# ----------------------------
Write-Host "Setting Splunk service to run as user '$SplunkUser'..."
$Service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
if ($Service) {
    $Service.Change($null,$null,$null,$null,$null,$null,"$env:COMPUTERNAME\$SplunkUser",$SplunkUserPassword)
} else {
    Write-Warning "Service '$ServiceName' not found. It may not have been installed correctly."
}

# ----------------------------
# 6. Start the Splunk service
# ----------------------------
Write-Host "Starting Splunk Forwarder service..."
Start-Service -Name $ServiceName

Write-Host "Splunk Universal Forwarder setup completed successfully!"
Write-Host "Random password for '$SplunkUser' is: $SplunkUserPassword (store this securely if needed)"