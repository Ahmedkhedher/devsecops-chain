# Creates a Desktop shortcut with no console window. Run once:
#   powershell -ExecutionPolicy Bypass -File .\scripts\make_shortcut.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\make_shortcut.ps1 -Web
#
# Without -Web it opens the tkinter desktop app; with -Web it opens the local
# browser console.

param([switch]$Web)

$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $project $(if ($Web) { "launch_web.pyw" } else { "launch.pyw" })
if (-not (Test-Path $launcher)) {
    throw "Launcher not found: $launcher"
}

$python = (py -c "import sys; print(sys.executable)").Trim()
if (-not $python) {
    throw "The 'py' launcher was not found on PATH."
}
$pythonw = Join-Path (Split-Path $python) "pythonw.exe"
if (-not (Test-Path $pythonw)) {
    $pythonw = "pythonw.exe"
}

$desktop = [Environment]::GetFolderPath("Desktop")
$name = if ($Web) { "DevSecOps Web Console.lnk" } else { "DevSecOps Chain.lnk" }
$shortcutPath = Join-Path $desktop $name

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = '"' + $launcher + '"'
$shortcut.WorkingDirectory = $project
$shortcut.Description = if ($Web) {
    "Browser console for risk-ranked vulnerability scans"
} else {
    "Scan a codebase for risk-ranked vulnerabilities"
}
$shortcut.IconLocation = "$pythonw,0"
$shortcut.Save()

Write-Host "Created shortcut: $shortcutPath"
