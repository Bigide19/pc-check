# Runs as SYSTEM; targets whoever is logged on interactively, so no account name is hardcoded.
$user = (Get-CimInstance Win32_ComputerSystem).UserName
$sid = (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value
$hku = "Registry::HKEY_USERS\$sid"
$profileDir = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid).LocalPath
