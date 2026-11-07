# Removes everything plant.ps1 created, and the restore point the fix run made. Runs as SYSTEM.
param([string]$PowerScheme = '')
. C:\work\tools\common.ps1
Remove-ItemProperty "$hku\Software\Microsoft\Windows\CurrentVersion\Run" -Name PcCheckTestUpdater -ErrorAction SilentlyContinue
Remove-ItemProperty "$hku\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name PcCheckTestUpdater -ErrorAction SilentlyContinue
Remove-Item (Join-Path $profileDir 'AppData\Roaming\a1b2c3d4') -Recurse -Force -ErrorAction SilentlyContinue
$is = "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty $is -Name ProxyEnable -Value 0 -Type DWord
Remove-ItemProperty $is -Name ProxyServer -ErrorAction SilentlyContinue
sc.exe stop PcCheckTestSvc | Out-Null
sc.exe delete PcCheckTestSvc | Out-Null
Remove-Item 'C:\ProgramData\x9k2m4p7' -Recurse -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName PcCheckTestTask -Confirm:$false -ErrorAction SilentlyContinue
$h = "$env:SystemRoot\System32\drivers\etc\hosts"
$lines = Get-Content $h | Where-Object { $_ -notmatch 'kbstar' }
Set-Content -Path $h -Value $lines -Encoding ASCII
$cp = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
Remove-ItemProperty $cp -Name HomepageLocation -ErrorAction SilentlyContinue
if ((Test-Path $cp) -and -not (Get-Item $cp).Property -and -not (Get-ChildItem $cp)) { Remove-Item $cp -Force }
if ($PowerScheme) { powercfg /setactive $PowerScheme }
vssadmin delete shadows /for=C: /all /quiet | Out-Null
Disable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
'cleaned'
