. C:\work\tools\common.ps1
$dir = Join-Path $profileDir 'AppData\Roaming\a1b2c3d4'
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Content "$dir\updater.exe" 'not a real exe'
Set-ItemProperty "$hku\Software\Microsoft\Windows\CurrentVersion\Run" -Name PcCheckTestUpdater -Value "`"$dir\updater.exe`" /silent"
$is = "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty $is -Name ProxyEnable -Value 1 -Type DWord
Set-ItemProperty $is -Name ProxyServer -Value '127.0.0.1:8888'
New-Item -ItemType Directory -Force 'C:\ProgramData\x9k2m4p7' | Out-Null
Set-Content 'C:\ProgramData\x9k2m4p7\svc.exe' 'not a real exe'
sc.exe create PcCheckTestSvc binPath= "C:\ProgramData\x9k2m4p7\svc.exe" start= auto | Out-Null
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -enc ZQB4AGkAdAA='
Register-ScheduledTask -TaskName PcCheckTestTask -Action $a -User SYSTEM -Force | Out-Null
Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`r`n1.2.3.4 www.kbstar.com"
New-Item -Force 'HKLM:\SOFTWARE\Policies\Google\Chrome' | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name HomepageLocation -Value 'http://example.invalid'
powercfg /duplicatescheme a1841308-3541-4fab-bc81-f71556f20b4a a1841308-3541-4fab-bc81-f71556f20b4a | Out-Null
powercfg /setactive a1841308-3541-4fab-bc81-f71556f20b4a
'planted'
