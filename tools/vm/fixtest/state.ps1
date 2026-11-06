. C:\work\tools\common.ps1
$ap = "$hku\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
$approved = (Get-ItemProperty $ap -Name PcCheckTestUpdater -ErrorAction SilentlyContinue).PcCheckTestUpdater
$is = Get-ItemProperty "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$svc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PcCheckTestSvc' -ErrorAction SilentlyContinue).Start
$task = (Get-ScheduledTask -TaskName PcCheckTestTask -ErrorAction SilentlyContinue).State
$hosts = [bool](Select-String -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Pattern 'kbstar' -Quiet)
$policy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue).HomepageLocation
$power = [regex]::Match((powercfg /getactivescheme | Out-String), '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}').Value
$rp = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Where-Object Description -eq 'PcCheck before fix').Count
[pscustomobject]@{
  startupApproved = $(if ($approved) { [BitConverter]::ToString($approved) } else { 'none' })
  proxyEnable = $is.ProxyEnable; proxyServer = $is.ProxyServer; serviceStart = $svc; taskState = [string]$task
  hostsHasKbstar = $hosts; chromeHomepage = $policy; power = $power; restorePoints = $rp
} | ConvertTo-Json -Compress
