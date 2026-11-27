<#
.SYNOPSIS
    Installs or uninstalls the native beam Windows client (BeamClient service + beam-tray.exe).

.DESCRIPTION
    Designed for zero-friction use via install.cmd (double-click) or PowerShell 5.1+.
    - Captures the interactive desktop user's SID before self-elevating via UAC.
    - Verifies wintun.dll SHA-256 (pinned Wintun 0.14.1 amd64) and Authenticode signature.
    - Validates client.toml with `beam-client.exe --check` BEFORE stopping any running service.
    - Installs binaries into "$env:ProgramFiles\beam" and config/ACL state into
      "$env:ProgramData\beam" (SYSTEM + Administrators only).
    - Registers and starts the LocalSystem Windows Service "BeamClient" with failure recovery.
    - Creates a Start Menu shortcut ("beam") and optionally registers unelevated logon
      auto-start via HKLM:\...\Run\BeamTray (zero UAC after install).
    - Supports clean removal via -Uninstall (or uninstall.cmd), including -KeepConfig.

.EXAMPLE
    .\install.ps1
    Installs from files next to this script (interactive prompt for auto-start).

.EXAMPLE
    .\install.ps1 -AutoStart -StartNow -NonInteractive
    Unattended install with login auto-start and immediate tray launch.

.EXAMPLE
    .\install.ps1 -Uninstall
    Cleanly stops beam-tray and BeamClient, cleans up routes, removes the service,
    auto-start entry, Start Menu shortcut, and installation/data directories.
#>

[CmdletBinding()]
param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "beam"),
    [string]$DataDir = (Join-Path $env:ProgramData "beam"),
    [string]$ServiceName = "BeamClient",
    [string]$ClientPath = "",
    [string]$TrayPath = "",
    [string]$WintunPath = "",
    [string]$ConfigPath = "",
    [string]$ClientSha256 = "",
    [string]$TraySha256 = "",
    [string]$AllowedUserSid = "",
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

$PinnedWintunSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$LegacyTaskName = "beam-tray"
$RunKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RunValueName = "BeamTray"
$ShortcutDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$ShortcutPath = Join-Path $ShortcutDir "beam.lnk"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevate {
    param(
        [System.Collections.IDictionary]$BoundParameters
    )
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )
    $hasAllowedSid = $false
    foreach ($kv in $BoundParameters.GetEnumerator()) {
        if ($kv.Key -eq "AllowedUserSid" -and -not [string]::IsNullOrWhiteSpace("$($kv.Value)")) {
            $hasAllowedSid = $true
        }
        if ($kv.Value -is [switch]) {
            if ($kv.Value.IsPresent) {
                $argList += "-$($kv.Key)"
            }
        } elseif ($null -ne $kv.Value -and "$($kv.Value)" -ne "") {
            $val = "$($kv.Value)".TrimEnd('\')
            $argList += "-$($kv.Key)"
            $argList += "`"$val`""
        }
    }

    # Capture the real interactive desktop user's SID before UAC elevation so
    # allowed-user.sid grants IPC access to the desktop user even if UAC
    # elevates to a separate Administrator account.
    if (-not $hasAllowedSid) {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if (-not [string]::IsNullOrWhiteSpace($currentSid)) {
            $argList += "-AllowedUserSid"
            $argList += "`"$currentSid`""
        }
    }

    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -PassThru -Wait
    exit $proc.ExitCode
}

function Get-Sha256FromSumsFile {
    param(
        [string]$SumsFile,
        [string]$FileName
    )
    if (-not (Test-Path -LiteralPath $SumsFile)) {
        return ""
    }
    $lines = Get-Content -LiteralPath $SumsFile -Encoding UTF8
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
            $hash = $Matches[1].ToLowerInvariant()
            $name = Split-Path -Leaf $Matches[2].Trim()
            if ($name.Equals($FileName, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $hash
            }
        }
    }
    return ""
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

function Verify-WintunSignature {
    param([string]$Path)

    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne "Valid") {
        throw "wintun.dll Authenticode signature is not Valid (Status: $($sig.Status)). Refusing to install."
    }
    Write-Host "  [OK] Authenticode signature verified: wintun.dll" -ForegroundColor Green
}

function Set-RestrictedDataDirAcl {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to use '$Path': directory is a reparse point / junction."
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $usersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")

    $acl.SetOwner($adminsSid)
    $acl.SetAccessRuleProtection($true, $false)

    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
               [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop = [System.Security.AccessControl.PropagationFlags]::None

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminsSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    # Built-in Users get read-only access for beam-client.log and status; no write/delete/create.
    # Secrets (client.toml, allowed-user.sid) override this with Set-RestrictedFileAcl.
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $usersSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $prop,
        [System.Security.AccessControl.AccessControlType]::Allow)))

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-RestrictedFileAcl {
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
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-SafeManagedDir {
    param(
        [string]$Path,
        [string]$ParamName
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Refusing to remove empty $ParamName path."
    }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')
    if ($full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove drive root '$full' ($ParamName)."
    }
    $protected = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:SystemRoot,
        $env:USERPROFILE,
        (Join-Path $env:SystemDrive "\Users")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        [System.IO.Path]::GetFullPath($_).TrimEnd('\')
    }
    foreach ($p in $protected) {
        if ($full.Equals($p, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove protected system directory '$full' ($ParamName)."
        }
    }
    # Require at least two path components below drive root (e.g. C:\Program Files\beam).
    $rel = $full.Substring($root.Length).TrimStart('\')
    if ([string]::IsNullOrWhiteSpace($rel) -or ($rel -split '\\').Count -lt 2) {
        throw "Refusing to remove top-level directory '$full' ($ParamName); use a dedicated subdirectory."
    }
}

function Stop-InstalledTray {
    param([string]$TargetDir)

    $resolvedDir = $TargetDir.TrimEnd('\').ToLowerInvariant()
    $trays = Get-Process -Name "beam-tray" -ErrorAction SilentlyContinue
    foreach ($p in $trays) {
        try {
            $pPath = $p.MainModule.FileName
            if ($pPath -and (Split-Path -Parent $pPath).TrimEnd('\').ToLowerInvariant() -eq $resolvedDir) {
                Write-Host "Stopping running beam-tray (PID $($p.Id))..."
                $null = Start-Process -FilePath $pPath -ArgumentList "--stop" -NoNewWindow -Wait -PassThru
                if (-not $p.WaitForExit(6000)) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Process may have already exited.
        }
    }
}

function Stop-LegacyCoreInInstallDir {
    param([string]$TargetDir)

    $resolvedDir = $TargetDir.TrimEnd('\').ToLowerInvariant()
    $legacyProcs = Get-Process -Name "sing-box" -ErrorAction SilentlyContinue
    foreach ($p in $legacyProcs) {
        try {
            $pPath = $p.MainModule.FileName
            if ($pPath -and (Split-Path -Parent $pPath).TrimEnd('\').ToLowerInvariant() -eq $resolvedDir) {
                Write-Host "Stopping legacy sing-box process (PID $($p.Id))..."
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $null = $p.WaitForExit(3000)
            }
        } catch {
            # Process may have already exited.
        }
    }
}

function Remove-LegacyScheduledTask {
    $existing = Get-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $LegacyTaskName -Confirm:$false
        Write-Host "  [OK] Removed legacy Scheduled Task '\$LegacyTaskName'." -ForegroundColor Green
    }
}

function Stop-BeamServiceIfRunning {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Write-Host "Stopping $ServiceName service..."
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $svc.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds(15)
                )
            } catch {
                Write-Warning "Service '$ServiceName' did not stop cleanly within 15s: $($_.Exception.Message)"
                return
            }
        }
        Write-Host "  [OK] Service $ServiceName is stopped." -ForegroundColor Green
    }
}

function Register-BeamService {
    param(
        [string]$ClientExe,
        [string]$ConfigFile
    )

    $binPath = "`"$ClientExe`" --service -c `"$ConfigFile`""
    $displayName = "Beam VPN Client"
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existing) {
        # Update ImagePath directly in SCM registry + Set-Service to avoid PS 5.1 sc.exe quote mangling.
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        Set-ItemProperty -Path $svcKey -Name "ImagePath" -Value $binPath
        Set-ItemProperty -Path $svcKey -Name "ObjectName" -Value "LocalSystem"
        Set-Service -Name $ServiceName -DisplayName $displayName -StartupType Automatic
        Write-Host "  [OK] Updated Windows service '$ServiceName'." -ForegroundColor Green
    } else {
        # New-Service calls CreateServiceW directly, preserving embedded quotes in paths with spaces.
        New-Service `
            -Name $ServiceName `
            -BinaryPathName $binPath `
            -DisplayName $displayName `
            -Description "Beam native VPN client service" `
            -StartupType Automatic | Out-Null
        Write-Host "  [OK] Created Windows service '$ServiceName'." -ForegroundColor Green
    }

    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure failure recovery for '$ServiceName' (sc.exe exit code $LASTEXITCODE)."
    }

    Start-Service -Name $ServiceName
    Write-Host "  [OK] Started Windows service '$ServiceName'." -ForegroundColor Green
}

function Set-TrayAutoStart {
    param(
        [string]$TrayExe,
        [bool]$Enable
    )

    if ($Enable) {
        if (-not (Test-Path -LiteralPath $RunKeyPath)) {
            New-Item -Path $RunKeyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RunKeyPath -Name $RunValueName -Value "`"$TrayExe`""
        Write-Host "  [OK] Registered unelevated logon auto-start ($RunValueName)." -ForegroundColor Green
    } else {
        Remove-TrayAutoStart
    }
}

function Remove-TrayAutoStart {
    if (Test-Path -LiteralPath $RunKeyPath) {
        $prop = Get-ItemProperty -Path $RunKeyPath -Name $RunValueName -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            Remove-ItemProperty -Path $RunKeyPath -Name $RunValueName -Force
            Write-Host "  [OK] Removed logon auto-start ($RunValueName)." -ForegroundColor Green
        }
    }
}

function New-StartMenuShortcut {
    param([string]$ExePath)

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $ExePath
    $shortcut.WorkingDirectory = Split-Path -Parent $ExePath
    $shortcut.IconLocation = "$ExePath,0"
    $shortcut.Description = "Beam VPN tray client"
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
        Stop-InstalledTray -TargetDir $InstallDir
        Stop-LegacyCoreInInstallDir -TargetDir $InstallDir
    }

    Stop-BeamServiceIfRunning

    $installedClient = Join-Path $InstallDir "beam-client.exe"
    if (Test-Path -LiteralPath $installedClient) {
        Write-Host "Running route cleanup (best-effort)..."
        try {
            & $installedClient --cleanup-routes | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Route cleanup exited with code $LASTEXITCODE."
            }
        } catch {
            Write-Warning "Route cleanup returned an error: $($_.Exception.Message)"
        }
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to delete Windows service '$ServiceName' (sc.exe exit code $LASTEXITCODE)."
        }
        Write-Host "  [OK] Deleted Windows service '$ServiceName'." -ForegroundColor Green
    }

    Remove-TrayAutoStart
    Remove-LegacyScheduledTask
    Remove-StartMenuShortcut

    if (Test-Path -LiteralPath $InstallDir) {
        Assert-SafeManagedDir -Path $InstallDir -ParamName "InstallDir"
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Host "  [OK] Removed $InstallDir." -ForegroundColor Green
    } else {
        Write-Host "  Install directory not found ($InstallDir); nothing to remove."
    }

    if (Test-Path -LiteralPath $DataDir) {
        Assert-SafeManagedDir -Path $DataDir -ParamName "DataDir"
        if ($KeepConfig) {
            Get-ChildItem -LiteralPath $DataDir -Force | Where-Object {
                $_.Name -ne "client.toml"
            } | Remove-Item -Recurse -Force
            Write-Host "  [OK] Cleaned $DataDir (kept client.toml)." -ForegroundColor Green
        } else {
            Remove-Item -LiteralPath $DataDir -Recurse -Force
            Write-Host "  [OK] Removed $DataDir." -ForegroundColor Green
        }
    }

    Write-Host "Uninstall complete." -ForegroundColor Green
}

function Invoke-Install {
    Write-Host "=== Installing beam Windows client ===" -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($ClientPath)) {
        $ClientPath = Join-Path $SourceDir "beam-client.exe"
    }
    if ([string]::IsNullOrWhiteSpace($TrayPath)) {
        $TrayPath = Join-Path $SourceDir "beam-tray.exe"
    }
    if ([string]::IsNullOrWhiteSpace($WintunPath)) {
        $WintunPath = Join-Path $SourceDir "wintun.dll"
    }

    if (-not (Test-Path -LiteralPath $ClientPath)) {
        throw "beam-client.exe not found at '$ClientPath'."
    }
    if (-not (Test-Path -LiteralPath $TrayPath)) {
        throw "beam-tray.exe not found at '$TrayPath'."
    }
    if (-not (Test-Path -LiteralPath $WintunPath)) {
        throw "wintun.dll not found at '$WintunPath'."
    }

    # Resolve optional SHA-256 checksums from SHA256SUMS if not supplied explicitly.
    $sumsFile = Join-Path $SourceDir "SHA256SUMS"
    if ([string]::IsNullOrWhiteSpace($ClientSha256)) {
        $ClientSha256 = Get-Sha256FromSumsFile -SumsFile $sumsFile -FileName (Split-Path -Leaf $ClientPath)
    }
    if ([string]::IsNullOrWhiteSpace($TraySha256)) {
        $TraySha256 = Get-Sha256FromSumsFile -SumsFile $sumsFile -FileName (Split-Path -Leaf $TrayPath)
    }

    Verify-Sha256 -Path $WintunPath -Expected $PinnedWintunSha256
    Verify-WintunSignature -Path $WintunPath
    if ([string]::IsNullOrWhiteSpace($ClientSha256)) {
        Write-Warning "No SHA-256 pin supplied (and SHA256SUMS not found) for beam-client.exe; installing unverified local binary."
    } else {
        Verify-Sha256 -Path $ClientPath -Expected $ClientSha256
    }
    if ([string]::IsNullOrWhiteSpace($TraySha256)) {
        Write-Warning "No SHA-256 pin supplied (and SHA256SUMS not found) for beam-tray.exe; installing unverified local binary."
    } else {
        Verify-Sha256 -Path $TrayPath -Expected $TraySha256
    }

    # Resolve AllowedUserSid (already captured pre-elevation if UAC ran).
    if ([string]::IsNullOrWhiteSpace($AllowedUserSid)) {
        $AllowedUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }
    if ($AllowedUserSid -notmatch '^S-1-[0-9-]+$') {
        throw "Invalid AllowedUserSid '$AllowedUserSid'."
    }

    # Config handling BEFORE touching any live files or stopping services.
    $destConfig = Join-Path $DataDir "client.toml"
    $usingExistingConfig = $false
    $resolvedConfig = ""

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            throw "Config file not found at '$ConfigPath'."
        }
        $resolvedConfig = $ConfigPath
    } else {
        $bundleConfig = Join-Path $SourceDir "client.toml"
        if (Test-Path -LiteralPath $bundleConfig) {
            $resolvedConfig = $bundleConfig
        } elseif (Test-Path -LiteralPath $destConfig) {
            $resolvedConfig = $destConfig
            $usingExistingConfig = $true
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedConfig)) {
        Write-Host "Validating $resolvedConfig with beam-client.exe --check..."
        & $ClientPath --check -c $resolvedConfig
        if ($LASTEXITCODE -ne 0) {
            throw "beam-client.exe --check failed (exit code $LASTEXITCODE). Fix client.toml and re-run install."
        }
        Write-Host "  [OK] client.toml passed beam-client.exe --check." -ForegroundColor Green
    } else {
        Write-Host "No client.toml found; proceeding with clean fresh install (import a vless:// link in the tray after install)." -ForegroundColor Yellow
    }

    $legacyConfigJson = Join-Path $InstallDir "config.json"
    if (Test-Path -LiteralPath $legacyConfigJson) {
        Write-Warning "Legacy sing-box config.json detected at '$legacyConfigJson'. The native client uses client.toml; import your vless:// link via the tray menu."
    }

    # Upgrade / legacy cleanup.
    if (Test-Path -LiteralPath $InstallDir) {
        Stop-InstalledTray -TargetDir $InstallDir
        Stop-LegacyCoreInInstallDir -TargetDir $InstallDir
    } else {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Remove-LegacyScheduledTask
    Stop-BeamServiceIfRunning

    if (-not (Test-Path -LiteralPath $DataDir)) {
        New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    }
    Set-RestrictedDataDirAcl -Path $DataDir

    # Copy binaries.
    $destClient = Join-Path $InstallDir "beam-client.exe"
    $destTray = Join-Path $InstallDir "beam-tray.exe"
    $destWintun = Join-Path $InstallDir "wintun.dll"
    $destSid = Join-Path $DataDir "allowed-user.sid"

    Copy-Item -LiteralPath $ClientPath -Destination $destClient -Force
    Copy-Item -LiteralPath $TrayPath -Destination $destTray -Force
    Copy-Item -LiteralPath $WintunPath -Destination $destWintun -Force

    if (-not [string]::IsNullOrWhiteSpace($resolvedConfig) -and -not $usingExistingConfig) {
        Copy-Item -LiteralPath $resolvedConfig -Destination $destConfig -Force
    }
    if (Test-Path -LiteralPath $destConfig) {
        Set-RestrictedFileAcl -Path $destConfig
    }

    # Write AllowedUserSid (UTF-8 without BOM) and lock ACL.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($destSid, $AllowedUserSid, $utf8NoBom)
    Set-RestrictedFileAcl -Path $destSid
    Write-Host "  [OK] Installed binaries to $InstallDir and restricted ACLs in $DataDir." -ForegroundColor Green

    Register-BeamService -ClientExe $destClient -ConfigFile $destConfig
    New-StartMenuShortcut -ExePath $destTray

    # Auto-start decision (unelevated HKLM Run entry, zero UAC).
    $wantAutoStart = $false
    if ($AutoStart) {
        $wantAutoStart = $true
    } elseif ($NoAutoStart) {
        $wantAutoStart = $false
    } elseif (-not $NonInteractive) {
        $ans = Read-Host "Start beam tray automatically when Windows logs in (no UAC prompt)? [Y/n]"
        $wantAutoStart = ([string]::IsNullOrWhiteSpace($ans) -or $ans -match '^[YyEe]')
    }
    Set-TrayAutoStart -TrayExe $destTray -Enable $wantAutoStart

    # Immediate launch decision (note: installer runs elevated; subsequent logons launch unelevated via HKLM Run).
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
    Write-Host "  Green (check) = Connected (WinTun up)"
    Write-Host "  Amber (...)   = Connecting / Reconnecting / Degraded"
    Write-Host "  Gray  (-)     = Disconnected"
    Write-Host "  Red   (!)     = Error (check BeamClient service / logs)"
}

if (-not (Test-IsAdmin)) {
    Invoke-SelfElevate -BoundParameters $PSBoundParameters
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
