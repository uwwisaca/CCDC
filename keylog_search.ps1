Write-Host "--- DEEP WINDOWS KEYLOGGER & HOOK SWEEP ---" -ForegroundColor Cyan

# 1. Search PowerShell logs for keylogging primitives
Write-Host "[!] Scanning ScriptBlock logs for Win32 API hooks:" -ForegroundColor Yellow
$Keywords = "GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookEx", "Get-Keystrokes"
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | 
    Where-Object { $_.Message -match ($Keywords -join "|") } | 
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap

# 2. Check for suspicious processes with no file description
Write-Host "`n[!] Checking for processes with no description or path:" -ForegroundColor Yellow
Get-Process | Where-Object { $_.Description -eq "" -or $_.Path -eq $null }

# 3. Audit 'Run' Registry keys for unauthorized EXEs
Write-Host "`n[!] Checking Registry Persistence:" -ForegroundColor Yellow
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
