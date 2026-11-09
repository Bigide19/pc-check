#!/usr/bin/env bash
# Drive the Parallels Windows VM from macOS: deploy the publish output, run headless, launch the GUI, capture the screen.
# prlctl exec runs as SYSTEM in session 0 (no visible windows); GUI runs go through an elevated
# interactive scheduled task so requireAdministrator does not stop at a UAC prompt.
set -euo pipefail

VM="${PCCHECK_VM:-Windows 11 Pro}"
# The account logged on in the VM, unless overridden.
VM_USER="${PCCHECK_VM_USER:-$(prlctl exec "$VM" --current-user cmd /c whoami 2>/dev/null | tr -d '\r')}"
APP_DIR='C:\work\pccheck'
TOOLS_DIR='C:\work\tools'
# Parallels share of ~/Projects, visible to the logged-in user only; follows the local repo folder name.
REPO_SHARE="Y:\\$(basename "$(cd "$(dirname "$0")/../.." && pwd)")"

# Non-zero exits are expected (e.g. Stop-Process with nothing running) and must not abort the helper.
ps() { prlctl exec "$VM" powershell -NoProfile -Command "$1" 2>&1 | iconv -f cp949 -t utf-8 || true; }

task() { # name exe args
  # Re-registering a task that is still marked running fails quietly, so stop it first.
  ps "Stop-ScheduledTask -TaskName '$1' -ErrorAction SilentlyContinue; \$a = New-ScheduledTaskAction -Execute '$2' -Argument '$3' -WorkingDirectory '$APP_DIR'; \
\$p = New-ScheduledTaskPrincipal -UserId '$VM_USER' -LogonType Interactive -RunLevel Highest; \
Register-ScheduledTask -TaskName '$1' -Action \$a -Principal \$p -Force | Out-Null; Start-ScheduledTask -TaskName '$1'; Start-Sleep 5"
}

ui() { task PcCheckUiHelper powershell.exe "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $TOOLS_DIR\\ui.ps1 $*"; }

case "${1:-}" in
  deploy)
    ps "Stop-Process -Name PcCheck -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force '$TOOLS_DIR' | Out-Null"
    prlctl exec "$VM" --current-user cmd /c "robocopy $REPO_SHARE\\publish $APP_DIR /MIR /XD PcCheck_* /NJH /NJS /NDL /NFL" >/dev/null || true
    # robocopy can fail silently (share not mounted yet); show what actually landed.
    ps "'deployed PcCheck.exe ' + (Get-Item '$APP_DIR\\PcCheck.exe').VersionInfo.ProductVersion"
    # Base64 so no quoting survives the trip; scripts must stay ASCII (PowerShell 5.1 reads BOM-less files as ANSI).
    for f in "$(dirname "$0")"/ui.ps1 "$(dirname "$0")"/fixtest/*.ps1; do
      b64=$(base64 < "$f" | tr -d '\n')
      ps "[IO.File]::WriteAllBytes('$TOOLS_DIR\\$(basename "$f")', [Convert]::FromBase64String('$b64'))"
    done
    ;;
  run-ps) # run a deployed script from tools/vm/fixtest as SYSTEM, e.g. run-ps state
    prlctl exec "$VM" powershell -NoProfile -ExecutionPolicy Bypass -File "$TOOLS_DIR\\$2.ps1" 2>&1 | iconv -f cp949 -t utf-8 || true
    ;;
  scan) # headless as SYSTEM; extra args pass through (e.g. --quick)
    shift
    args=$(printf "'%s'," scan "$@"); args=${args%,}
    ps "\$p = Start-Process '$APP_DIR\\PcCheck.exe' -ArgumentList $args -Wait -PassThru; 'exit=' + \$p.ExitCode; \
\$d = Get-ChildItem '$APP_DIR' -Directory -Filter 'PcCheck_*' | Sort-Object Name | Select-Object -Last 1; \$d.FullName; \
Get-Content (Join-Path \$d.FullName 'findings.json') -Encoding UTF8"
    ;;
  gui) # gui [--mock]
    ps "Stop-Process -Name PcCheck -Force -ErrorAction SilentlyContinue"
    task PcCheckUi "$APP_DIR\\PcCheck.exe" "${2:---gui}"
    ui
    ;;
  tab)    ui -Index "$2" ;;      # select result tab by index
  click)  ui -Button "$2" ;;     # invoke the Nth named button
  invoke) ui -Id "$2" ;;         # invoke/toggle/select the element with this AutomationId
  max)    ui -Maximize ;;
  front)  ui ;;
  capture) prlctl capture "$VM" --file "$2" ;;
  shot) # shot FILE [MAXWIDTH]: screenshot taken inside the guest session (prlctl capture can return an empty file)
    # Elevated tasks cannot see the Y: share, so save inside the guest and pull it out as base64 through SYSTEM.
    ps "Stop-Process -Name WindowsTerminal,OpenConsole -Force -ErrorAction SilentlyContinue; Remove-Item C:\\work\\shot.png -ErrorAction SilentlyContinue"
    s="Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
Add-Type -Name D -Namespace W -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool SetProcessDPIAware();'; \
[W.D]::SetProcessDPIAware() | Out-Null; \$b = [Windows.Forms.Screen]::PrimaryScreen.Bounds; \
\$m = New-Object Drawing.Bitmap \$b.Width, \$b.Height; [Drawing.Graphics]::FromImage(\$m).CopyFromScreen(\$b.X, \$b.Y, 0, 0, \$b.Size); \
\$w = [Math]::Min(${3:-1920}, \$b.Width); \$h = [int](\$b.Height * \$w / \$b.Width); \$o = New-Object Drawing.Bitmap \$w, \$h; \
\$g = [Drawing.Graphics]::FromImage(\$o); \$g.InterpolationMode = 'HighQualityBicubic'; \$g.DrawImage(\$m, 0, 0, \$w, \$h); \$o.Save('C:\\work\\shot.png')"
    task PcCheckShot powershell.exe "-NoProfile -WindowStyle Hidden -EncodedCommand $(printf '%s' "$s" | iconv -t UTF-16LE | base64 | tr -d '\n')"
    prlctl exec "$VM" powershell -NoProfile -Command "\$f = 'C:\\work\\shot.png'; for (\$i = 0; \$i -lt 30 -and -not (Test-Path \$f); \$i++) { Start-Sleep 1 }; do { \$n = (Get-Item \$f).Length; Start-Sleep 1 } while (\$n -ne (Get-Item \$f).Length); [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\work\\shot.png'))" | tr -d '\r\n' | base64 -d > "$2"
    ;;
  *) echo "usage: $0 deploy | scan [--quick] | gui [--mock] | tab N | click N | invoke ID | max | front | capture FILE | shot FILE [MAXWIDTH] | run-ps NAME" >&2; exit 2 ;;
esac
