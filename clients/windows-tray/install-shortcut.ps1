param(
    [switch]$Startup
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'beam-tray.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    throw "beam-tray.exe not found. Run build.sh first."
}

$folder = if ($Startup) {
    [Environment]::GetFolderPath('Startup')
} else {
    [Environment]::GetFolderPath('Desktop')
}

$link = Join-Path $folder 'beam sing-box.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($link)
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = $root
$shortcut.IconLocation = "$exe,0"
$shortcut.Description = 'beam sing-box tray'
$shortcut.Save()

Write-Host "shortcut: $link"
