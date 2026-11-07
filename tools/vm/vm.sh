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
REPO_SHARE='Y:\pitstop'   # Parallels share of ~/Projects, visible to the logged-in user only

# Non-zero exits are expected (e.g. Stop-Process with nothing running) and must not abort the helper.
ps() { prlctl exec "$VM" powershell -NoProfile -Command "$1" 2>&1 | iconv -f cp949 -t utf-8 || true; }

task() { # name exe args
  ps "\$a = New-ScheduledTaskAction -Execute '$2' -Argument '$3' -WorkingDirectory '$APP_DIR'; \
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
  *) echo "usage: $0 deploy | scan [--quick] | gui [--mock] | tab N | click N | invoke ID | max | front | capture FILE | run-ps NAME" >&2; exit 2 ;;
esac
