#Password Reset and User Session Termination for Windows

#Ensure script runs as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "ERROR: Must be run as Administrator"
    exit 1
}

$User = "sysadmin"

#Check if user exists
if (-Not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
    Write-Error "ERROR: User '$User' does not exist. Aborting."
    exit 1
}

Write-Host "Password resetting in case of compromise`n"

#Reset password function
function Reset-Password {
    param ()

    $TargetUser = Read-Host "Which user's password would you like to reset?"

    $LocalUser = Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue
    if (-Not $LocalUser) {
        Write-Host "ERROR: User '$TargetUser' does not exist."
        return
    }

    $SecurePass = Read-Host "Enter new password for $TargetUser" -AsSecureString
    Set-LocalUser -Name $TargetUser -Password $SecurePass
    Write-Host "Password updated for $TargetUser`n"
}

#Password reset loop (will continue to run as long as user needs to change more passwords)
while ($true) {
    Reset-Password

    $Another = Read-Host "Would you like to change another user's password? (yes/no)"
    if ($Another -notmatch "^(?i)yes$") {
        break
    }
}

#Kill user sessions in case of account compromise (password reset -> kill sessions)
$KillSessions = Read-Host "Kill ALL user sessions (including Administrator)? (yes/no)"
if ($KillSessions -match "^(?i)yes$") {
    Write-Host "Terminating all user sessions except current..."

    $CurrentSessionId = (qwinsta | Where-Object { $_ -match $env:USERNAME } | ForEach-Object { ($_ -split '\s+')[2] })[0]

    $Sessions = qwinsta | ForEach-Object {
        $cols = ($_ -split '\s+')
        if ($cols.Count -ge 3) {
            [PSCustomObject]@{ Username = $cols[1]; SessionId = $cols[2] }
        }
    } | Where-Object { $_.Username -ne $env:USERNAME -and $_.Username -ne $null }

    foreach ($s in $Sessions) {
        logoff $s.SessionId /V
    }

    Write-Host "All other user sessions terminated`n"
} else {
    Write-Host "Skipping session termination`n"
}

Write-Host "Password refresh complete. Remember to logout so administrator password changes take effect!"