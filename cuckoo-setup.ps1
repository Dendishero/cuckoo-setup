<#
 
.SYNOPSIS
This is a simple Powershell script do basic setup tasks for a cuckoo guest
 
.DESCRIPTION
This script does a variety of configuration tasks required for Windows guests to work with cuckoo.  See NOTES section for details

.EXAMPLE
./cuckoo-setup.ps1 -username cuckoo -password password -deps -extras
 
.NOTES
Install Dependencies
    - Python
    - PIL
Install Extras
    - Adobe Reader
    - Office
    - etc.
    - Any installer the user wants can be placed in the extras folder

Disable Windows Firewall
    - Required for cuckoo agent to communicate

Modify Registry
    - Turn off CHKDSK
    - Enable auto logon
    - Disable Screen Saver
    - Enable Remote RPC
    - Allow for remote rebooting
    - Disable UAC
 
.LINK
<put online somewhere maybe?> 
 
#>

# Parameter list
param (
    [string]$username = $( throw"-username is required."),
    [string]$password = $( Read-Host "Input password, please" ),
    [switch]$extras = $false,
    [switch]$deps = $false,
    [switch]$custom = $false
)


if ($deps -eq $true) {
    Write-Host '[+] Installing Dependencies'
    $items = gci 'deps' -Name
    foreach ($item in $items) {
        Write-Host '[+] Installing' $item
        & $item /quiet /norestart
    }
}


if ($extras -eq $true) {
    Write-Host '[+] Installing Extras'
    $items = gci 'extras' -Name
    foreach ($item in $items) {
        Write-Host '[+] Installing' $item
        & $item /quiet /norestart
    }
}

# testing...
if ($custom -eq $true) {
    $adobe = Read-Host "Which version of Adobe would you like to install?"
    Write-Host $adobe
}

Write-Host '[+] Installing agent'
cp agent\agent.py "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\agent.pyw"

Write-Host '[+] Disabling Firewall'
netsh advfirewall set allprofiles state off

Write-Host '[+] Modifying Registry'

# Turn off CHKDSK for C Drive
reg add "hklm\system\CurrentControlSet\Control\Session Manager" /v BootExecute /d "autocheck autochk /k:C *" /t REG_MULTI_SZ /f 

# Enable auto logon for user
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName /d $username /t REG_SZ /f 
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /d $password /t REG_SZ /f 
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogone /d 1 /t REG_SZ /f 

# Disable Screen Saver 
reg add "hkcu\Control Panel\Desktop" /v ScreenSaveActive /d 0 /t REG_SZ /f 

# Enable Remote RPC
reg add "hklm\system\CurrentControlSet\Control\TerminalServer" /v AllowRemoteRPC /d 0x01 /t REG_DWORD /f 

# Stupid reg key that allows for RPC rebooting
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /d 0x01 /t REG_DWORD /f

# Disable UAC
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /d 0x00 /t REG_DWORD /f

