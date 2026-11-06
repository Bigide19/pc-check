param([int]$Index = -1, [int]$Button = -1, [string]$Id = '', [switch]$Maximize)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -Name W -Namespace U -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c); [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);'
Get-Process Taskmgr -ErrorAction SilentlyContinue | ForEach-Object { [U.W]::ShowWindow($_.MainWindowHandle, 6) | Out-Null }
$p = Get-Process PcCheck | Select-Object -First 1
[U.W]::ShowWindow($p.MainWindowHandle, $(if ($Maximize) { 3 } else { 9 })) | Out-Null
[U.W]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
if ($Index -ge 0) {
  $root = [Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
  $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::TabItem)
  $tabs = $root.FindAll([Windows.Automation.TreeScope]::Descendants, $cond)
  $tabs[$Index].GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern).Select()
}
if ($Button -ge 0) {
  $root = [Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
  $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button)
  $btns = $root.FindAll([Windows.Automation.TreeScope]::Descendants, $cond) | Where-Object { $_.Current.AutomationId -eq '' -and $_.Current.Name -ne '' }
  $btns[$Button].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
}
if ($Id -ne '') {
  $root = [Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
  $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
  $el = $root.FindFirst([Windows.Automation.TreeScope]::Descendants, $cond)
  $pattern = $null
  if ($el.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) { $pattern.Invoke() }
  elseif ($el.TryGetCurrentPattern([Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)) { $pattern.Toggle() }
  elseif ($el.TryGetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) { $pattern.Select() }
}
