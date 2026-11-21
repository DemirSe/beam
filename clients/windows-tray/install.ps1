<#
.SYNOPSIS
    Installs or uninstalls the beam Windows tray client (beam-tray.exe + sing-box.exe).

.DESCRIPTION
    Designed for zero-friction use via install.cmd (double-click) or PowerShell 5.1+.
    - Self-elevates via UAC when not running as Administrator.
    - Validates config.json with `sing-box.exe check` BEFORE stopping any running tunnel.
    - Installs into "$env:ProgramFiles\beam" and locks down config.json ACLs
      (SYSTEM + Administrators only).
    - Creates a Start Menu shortcut ("beam").
    - Optionally registers a Scheduled Task ("\beam-tray", RunLevel Highest) so
      beam-tray starts at logon without a UAC prompt.
    - Supports clean removal via -Uninstall (or uninstall.cmd).

.EXAMPLE
    .\install.ps1
    Installs from files next to this script (interactive prompts for auto-start).

.EXAMPLE
    .\install.ps1 -AutoStart -StartNow -NonInteractive
    Unattended install with login auto-start and immediate launch.

.EXAMPLE
    .\install.ps1 -Uninstall
    Cleanly stops beam-tray, removes the Scheduled Task, Start Menu shortcut,
    and installation directory.
#>

[CmdletBinding()]
param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "beam"),
    [string]$CorePath = "",
    [string]$TrayPath = "",
    [string]$ConfigPath = "",
    [string]$CoreSha256 = "",
    [string]$TraySha256 = "",
    [switch]$AutoStart,
    [switch]$NoAutoStart,
    [switch]$StartNow,
    [switch]$NoStart,
    [switch]$Uninstall,
    [switch]$KeepConfig,
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TaskName = "beam-tray"
$ShortcutDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$ShortcutPath = Join-Path $ShortcutDir "beam.lnk"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevate {
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) {
            if ($kv.Value.IsPresent) {
                $argList += "-$($kv.Key)"
            }
        } elseif ($null -ne $kv.Value -and "$($kv.Value)" -ne "") {
            $argList += "-$($kv.Key)"
            $argList += "`"$($kv.Value)`""
        }
    }

    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -PassThru -Wait
    exit $proc.ExitCode
}

function Verify-Sha256 {
    param(
        [string]$Path,
        [string]$Expected
    )
    if ([string]::IsNullOrWhiteSpace($Expected)) {
        return
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    $want = $Expected.Trim().ToLowerInvariant()
    if ($actual -ne $want) {
        throw "SHA-256 mismatch for '$Path': expected $want, got $actual"
    }
    Write-Host "  [OK] SHA-256 verified: $(Split-Path -Leaf $Path)" -ForegroundColor Green
}

function Stop-InstalledProcesses {
    param([string]$TargetDir)

    $resolvedDir = $TargetDir.TrimEnd('\').ToLowerInvariant()

    # Close beam-tray first so it gracefully shuts down sing-box (WFP + TUN DNS cleanup).
    $trays = Get-Process -Name "beam-tray" -ErrorAction SilentlyContinue
    foreach ($p in $trays) {
        try {
            $pPath = $p.MainModule.FileName
            if ($pPath -and (Split-Path -Parent $pPath).TrimEnd('\').ToLowerInvariant() -eq $resolvedDir) {
                Write-Host "Stopping running beam-tray (PID $($p.Id))..."
                $null = $p.CloseMainWindow()
                if (-not $p.WaitForExit(6000)) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Process may have already exited.
        }
    }

    # Ensure no orphaned sing-box.exe remains in InstallDir.
    Start-Sleep -Milliseconds 300
    $cores = Get-Process -Name "sing-box" -ErrorAction SilentlyContinue
    foreach ($p in $cores) {
        try {
            $pPath = $p.MainModule.FileName
            if ($pPath -and (Split-Path -Parent $pPath).TrimEnd('\').ToLowerInvariant() -eq $resolvedDir) {
                Write-Host "Stopping remaining sing-box (PID $($p.Id))..."
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $null = $p.WaitForExit(3000)
            }
        } catch {
            # Process may have already exited.
        }
    }
}

function Set-RestrictedConfigAcl {
    param([string]$Path)

    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")

    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl.AddAccessRule($ruleSystem)
    $acl.AddAccessRule($ruleAdmins)
    Set-Acl -Path $Path -AclObject $acl
}

function Register-AutoStartTask {
    param([string]$ExePath)

    $userId = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory (Split-Path -Parent $ExePath)
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Start beam-tray at user logon (elevated, no UAC prompt)" `
        -Force | Out-Null

    Write-Host "  [OK] Auto-start Scheduled Task '\$TaskName' registered for $userId." -ForegroundColor Green
}

function Unregister-AutoStartTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  [OK] Removed Scheduled Task '\$TaskName'." -ForegroundColor Green
    }
}

function New-StartMenuShortcut {
    param([string]$ExePath)

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $ExePath
    $shortcut.WorkingDirectory = Split-Path -Parent $ExePath
    $shortcut.IconLocation = "$ExePath,0"
    $shortcut.Description = "beam sing-box tray client"
    $shortcut.Save()
    Write-Host "  [OK] Start Menu shortcut created: $ShortcutPath" -ForegroundColor Green
}

function Remove-StartMenuShortcut {
    if (Test-Path -LiteralPath $ShortcutPath) {
        Remove-Item -LiteralPath $ShortcutPath -Force
        Write-Host "  [OK] Removed Start Menu shortcut." -ForegroundColor Green
    }
}

function Invoke-Uninstall {
    Write-Host "=== Uninstalling beam Windows client ===" -ForegroundColor Cyan

    if (Test-Path -LiteralPath $InstallDir) {
        Stop-InstalledProcesses -TargetDir $InstallDir
    }
    Unregister-AutoStartTask
    Remove-StartMenuShortcut

    if (Test-Path -LiteralPath $InstallDir) {
        if ($KeepConfig) {
            Get-ChildItem -LiteralPath $InstallDir -Force | Where-Object {
                $_.Name -ne "config.json"
            } | Remove-Item -Recurse -Force
            Write-Host "  [OK] Removed binaries from $InstallDir (kept config.json)." -ForegroundColor Green
        } else {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force
            Write-Host "  [OK] Removed $InstallDir." -ForegroundColor Green
        }
    } else {
        Write-Host "  Install directory not found ($InstallDir); nothing to remove."
    }

    Write-Host "Uninstall complete." -ForegroundColor Green
}

function Invoke-Install {
    Write-Host "=== Installing beam Windows client ===" -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($TrayPath)) {
        $TrayPath = Join-Path $SourceDir "beam-tray.exe"
    }
    if ([string]::IsNullOrWhiteSpace($CorePath)) {
        $CorePath = Join-Path $SourceDir "sing-box.exe"
    }

    $installedConfig = Join-Path $InstallDir "config.json"
    $usingExistingConfig = $false
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $bundleConfig = Join-Path $SourceDir "config.json"
        if (Test-Path -LiteralPath $bundleConfig) {
            $ConfigPath = $bundleConfig
        } elseif (Test-Path -LiteralPath $installedConfig) {
            $ConfigPath = $installedConfig
            $usingExistingConfig = $true
        } else {
            throw "config.json not found next to install.ps1 and no existing $installedConfig found. Copy config.example.json to config.json, fill in your server details, and run again."
        }
    }

    if (-not (Test-Path -LiteralPath $TrayPath)) {
        throw "beam-tray.exe not found at '$TrayPath'. Build it with clients/windows-tray/build.sh or pass -TrayPath."
    }
    if (-not (Test-Path -LiteralPath $CorePath)) {
        throw "sing-box.exe not found at '$CorePath'. Place sing-box 1.15+ next to install.ps1 or pass -CorePath."
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "config.json not found at '$ConfigPath'."
    }

    Verify-Sha256 -Path $TrayPath -Expected $TraySha256
    Verify-Sha256 -Path $CorePath -Expected $CoreSha256

    # Warn if placeholder UUID is still present.
    $rawConfig = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
    if ($rawConfig -match "00000000-0000-0000-0000-000000000000") {
        Write-Warning "config.json still contains the placeholder UUID (00000000-...). Replace placeholders before connecting."
    }

    # Validate config BEFORE touching any live installation.
    Write-Host "Validating config.json with sing-box check..."
    $checkProc = Start-Process -FilePath $CorePath -ArgumentList @("check", "-c", "`"$ConfigPath`"") -NoNewWindow -Wait -PassThru
    if ($checkProc.ExitCode -ne 0) {
        throw "sing-box check failed (exit code $($checkProc.ExitCode)). Fix config.json and re-run install."
    }
    Write-Host "  [OK] config.json passed sing-box check." -ForegroundColor Green

    # Stop running instance cleanly before replacing binaries.
    if (Test-Path -LiteralPath $InstallDir) {
        Stop-InstalledProcesses -TargetDir $InstallDir
    } else {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $destTray = Join-Path $InstallDir "beam-tray.exe"
    $destCore = Join-Path $InstallDir "sing-box.exe"
    $destConfig = Join-Path $InstallDir "config.json"

    Copy-Item -LiteralPath $TrayPath -Destination $destTray -Force
    Copy-Item -LiteralPath $CorePath -Destination $destCore -Force

    # Copy wintun.dll if shipped beside sing-box.exe.
    $wintunSrc = Join-Path (Split-Path -Parent $CorePath) "wintun.dll"
    if (Test-Path -LiteralPath $wintunSrc) {
        Copy-Item -LiteralPath $wintunSrc -Destination (Join-Path $InstallDir "wintun.dll") -Force
        Write-Host "  [OK] Copied wintun.dll." -ForegroundColor Green
    }

    if (-not $usingExistingConfig) {
        Copy-Item -LiteralPath $ConfigPath -Destination $destConfig -Force
    }
    Set-RestrictedConfigAcl -Path $destConfig
    Write-Host "  [OK] Installed files to $InstallDir (config.json ACL restricted)." -ForegroundColor Green

    New-StartMenuShortcut -ExePath $destTray

    # Auto-start decision.
    $wantAutoStart = $false
    if ($AutoStart) {
        $wantAutoStart = $true
    } elseif ($NoAutoStart) {
        $wantAutoStart = $false
    } elseif (-not $NonInteractive) {
        $ans = Read-Host "Start beam automatically when Windows logs in (no UAC prompt)? [Y/n]"
        $wantAutoStart = ([string]::IsNullOrWhiteSpace($ans) -or $ans -match '^[YyEe]')
    }

    if ($wantAutoStart) {
        Register-AutoStartTask -ExePath $destTray
    } else {
        Unregister-AutoStartTask
    }

    # Immediate launch decision.
    $wantStart = $true
    if ($NoStart) {
        $wantStart = $false
    } elseif ($StartNow) {
        $wantStart = $true
    }

    if ($wantStart) {
        Write-Host "Launching beam-tray.exe..."
        Start-Process -FilePath $destTray -WorkingDirectory $InstallDir
    }

    Write-Host ""
    Write-Host "Install complete! Look for the beam icon in the system tray:" -ForegroundColor Green
    Write-Host "  Green (check) = Connected (TUN up)"
    Write-Host "  Amber (...)   = Connecting / Disconnecting"
    Write-Host "  Gray  (-)     = Disconnected"
    Write-Host "  Red   (!)     = Error (open sing-box.log from the tray menu)"
}

if (-not (Test-IsAdmin)) {
    Invoke-SelfElevate
}

try {
    if ($Uninstall) {
        Invoke-Uninstall
    } else {
        Invoke-Install
    }
    if (-not $NonInteractive) {
        Start-Sleep -Seconds 2
    }
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if (-not $NonInteractive) {
        $null = Read-Host "Press Enter to close"
    }
    exit 1
}
