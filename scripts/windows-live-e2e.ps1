<#
.SYNOPSIS
    Live end-to-end check of the packaged native Windows client against a VPS.

.DESCRIPTION
    Tests the exact user install path: the packaged zip from
    scripts/release-windows-tray.sh is extracted to a clean directory, installed
    with install.ps1 headlessly, driven over the \\.\pipe\beam-client-ipc pipe
    (single-line framing per crates/beam-client/src/win_ipc.rs: STATUS,
    CONNECT, DISCONNECT, IMPORT_LINK <vless://...>), then uninstalled.

    Secret hygiene: the BEAM_LIVE_VLESS_LINK value, UUID, public key, short id,
    raw client.toml, and VPS host/IP are NEVER printed. Only boolean/numeric
    verdicts are reported. Always wrapped so runner connectivity is restored:
    the caller runs the whole flow in try { } finally { } and the workflow
    disconnects + uninstalls even on failure.

.EXAMPLE
    $env:BEAM_LIVE_VLESS_LINK = 'vless://...'
    pwsh -File scripts/windows-live-e2e.ps1 -PackageDir C:\extracted-zip
#>

[CmdletBinding()]
param(
    [string]$PackageDir = (Join-Path $env:RUNNER_TEMP 'windows-live-e2e\extracted')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'BeamClient'
$PipeName = 'beam-client-ipc'
$IpifyUrl = 'https://api.ipify.org'
$ProbeUrl = 'https://example.com'

$verdicts = New-Object System.Collections.Generic.List[string]
$failures = 0

function Add-Verdict {
    param([string]$Line)
    # Verdict lines are boolean/numeric only; never pass secret material here.
    $verdicts.Add($Line)
    Write-Host $Line
}

function Invoke-Ipc {
    param(
        [Parameter(Mandatory = $true)][string]$Line,
        [int]$TimeoutMs = 5000
    )
    # Log only the command token; the IMPORT_LINK argument carries the secret.
    $token = ($Line -split ' ', 2)[0]
    Write-Host "ipc> $token"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $client.Connect($TimeoutMs)
        $writer = New-Object System.IO.StreamWriter($client, $utf8NoBom, 1024, $true)
        $writer.NewLine = "`n"
        $writer.AutoFlush = $true
        $writeTask = $writer.WriteLineAsync($Line)
        if (-not $writeTask.Wait($TimeoutMs)) {
            throw 'ipc_write_timeout'
        }
        $writer.Flush()
        $reader = New-Object System.IO.StreamReader($client, $utf8NoBom, $false, 1024, $true)
        $readTask = $reader.ReadLineAsync()
        if (-not $readTask.Wait($TimeoutMs)) {
            throw 'ipc_read_timeout'
        }
        $reply = $readTask.Result
        if ([string]::IsNullOrEmpty($reply)) { throw 'empty IPC reply' }
        return $reply
    } finally {
        $client.Dispose()
    }
}

function Read-Status {
    $reply = Invoke-Ipc -Line 'STATUS'
    if ($reply -notmatch '^OK ') { throw 'status_not_ok' }
    $fields = @{}
    foreach ($pair in ($reply.Substring(3) -split ' ')) {
        $kv = $pair -split '=', 2
        if ($kv.Count -eq 2) { $fields[$kv[0]] = $kv[1] }
    }
    return $fields
}

function Get-PublicIpv4 {
    try {
        $ip = (Invoke-RestMethod -Uri $IpifyUrl -TimeoutSec 10).Trim()
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
        return ''
    } catch {
        return ''
    }
}

function Test-BeamAdapterUp {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Beam*' }
    return ($null -ne $adapters) -and
        (($adapters | Where-Object { $_.Status -eq 'Up' } | Measure-Object).Count -gt 0)
}

$exitCode = 0
try {
    $link = $env:BEAM_LIVE_VLESS_LINK
    if ([string]::IsNullOrWhiteSpace($link)) {
        throw 'BEAM_LIVE_VLESS_LINK is empty or unset.'
    }
    if ($link -notmatch '^vless://') {
        throw 'BEAM_LIVE_VLESS_LINK does not start with vless://.'
    }
    Add-Verdict 'secret_present=true'

    # Mask the VPS host/IP and every parsed secret field before any check runs.
    $hostMatch = [regex]::Match($link, '^vless://(?<user>[^@]+)@(?<host>\[[^\]]+\]|[^:/?#]+)')
    $vpsHost = if ($hostMatch.Success) { $hostMatch.Groups['host'].Value.Trim('[', ']') } else { '' }
    $vpsUser = if ($hostMatch.Success) { $hostMatch.Groups['user'].Value } else { '' }
    if ($vpsUser -ne '') { Write-Host ("::add-mask::" + $vpsUser) }
    foreach ($pattern in @('(?<=pbk=)[^&#]+', '(?<=sid=)[^&#]+')) {
        $m = [regex]::Match($link, $pattern)
        if ($m.Success) { Write-Host ("::add-mask::" + $m.Value) }
    }
    if ($vpsHost -ne '') { Write-Host ("::add-mask::" + $vpsHost) }
    $vpsIpv4 = ''
    if ($vpsHost -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $vpsIpv4 = $vpsHost
    } elseif ($vpsHost -ne '') {
        try {
            $vpsIpv4 = ([System.Net.Dns]::GetHostAddresses($vpsHost) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                Select-Object -First 1).ToString()
        } catch {
            $vpsIpv4 = ''
        }
    }
    if ($vpsIpv4 -ne '') { Write-Host ("::add-mask::" + $vpsIpv4) }

    $baseline = Get-PublicIpv4
    Add-Verdict ("baseline_egress_reachable=" + ($baseline -ne '').ToString().ToLowerInvariant())

    $installPs1 = Join-Path $PackageDir 'install.ps1'
    if (-not (Test-Path -LiteralPath $installPs1)) {
        throw "install.ps1 not found under $PackageDir."
    }
    # Run install.ps1 via Windows PowerShell 5.1 (matching install.cmd) so exit codes are isolated.
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installPs1 -NoAutoStart -NoStart -NonInteractive
    if ($LASTEXITCODE -ne 0) { throw "install_failed exit=$LASTEXITCODE" }

    $running = $false
    for ($i = 0; $i -lt 20; $i++) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (($null -ne $svc) -and ($svc.Status -eq 'Running')) { $running = $true; break }
        Start-Sleep -Seconds 1
    }
    Add-Verdict ('service_running=' + $running.ToString().ToLowerInvariant())
    if (-not $running) { throw 'service_not_running' }

    # Pipe liveness before import. Replies never carry key material.
    $status = Read-Status
    Add-Verdict ('ipc_status_ok=' + ($status['state'] -ne $null).ToString().ToLowerInvariant())

    $importReply = Invoke-Ipc -Line ("IMPORT_LINK " + $link)
    $importOk = $importReply.StartsWith('OK ')
    Add-Verdict ('import_ok=' + $importOk.ToString().ToLowerInvariant())
    if (-not $importOk) { throw 'import_failed' }

    $connectReply = Invoke-Ipc -Line 'CONNECT'
    $connectAccepted = $connectReply.StartsWith('OK ')
    Add-Verdict ('connect_accepted=' + $connectAccepted.ToString().ToLowerInvariant())
    if (-not $connectAccepted) { throw 'connect_rejected' }

    $connected = $false
    $rttMs = 'none'
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
        $status = Read-Status
        if ($status['state'] -eq 'connected') {
            $connected = $true
            $rttMs = $status['rtt_ms']
            break
        }
        if ($status['state'] -eq 'error') { break }
    }
    Add-Verdict ('connected=' + $connected.ToString().ToLowerInvariant())
    $rttNum = 0
    $rttOk = [int]::TryParse($rttMs, [ref]$rttNum)
    Add-Verdict ('rtt_ms=' + $(if ($rttOk) { $rttMs } else { 'none' }))
    if (-not $connected) { throw 'never_connected' }

    Add-Verdict ('wintun_adapter_up=' + (Test-BeamAdapterUp).ToString().ToLowerInvariant())
    if (-not (Test-BeamAdapterUp)) { throw 'wintun_not_up' }

    $egress = Get-PublicIpv4
    Add-Verdict ('egress_reachable=' + ($egress -ne '').ToString().ToLowerInvariant())
    Add-Verdict ('egress_ip_changed=' + (($egress -ne '') -and ($egress -ne $baseline)).ToString().ToLowerInvariant())
    $matchesVps = ($egress -ne '') -and ($vpsIpv4 -ne '') -and ($egress -eq $vpsIpv4)
    Add-Verdict ('egress_matches_vps=' + $matchesVps.ToString().ToLowerInvariant())
    if ($egress -eq '') { throw 'no_egress_through_tunnel' }
    if (-not (($egress -ne $baseline) -and $matchesVps)) { throw 'egress_not_via_vps' }

    $dnsOk = $false
    try {
        $answer = Resolve-DnsName -Name 'example.com' -ErrorAction Stop
        $dnsOk = ($null -ne $answer)
    } catch {
        $dnsOk = $false
    }
    Add-Verdict ('dns_ok=' + $dnsOk.ToString().ToLowerInvariant())
    $httpsOk = $false
    try {
        $null = Invoke-WebRequest -Uri $ProbeUrl -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        $httpsOk = $true
    } catch {
        $httpsOk = $false
    }
    Add-Verdict ('https_ok=' + $httpsOk.ToString().ToLowerInvariant())
    if (-not ($dnsOk -and $httpsOk)) { throw 'dns_or_https_failed' }

    # Best-effort WFP/callout presence via the filter engine service state.
    $wfpOk = $false
    try {
        $bfe = Get-Service -Name 'BFE' -ErrorAction Stop
        $wfpOk = ($bfe.Status -eq 'Running')
    } catch {
        $wfpOk = $false
    }
    Add-Verdict ('wfp_bfe_running=' + $wfpOk.ToString().ToLowerInvariant())

    $discReply = Invoke-Ipc -Line 'DISCONNECT'
    Add-Verdict ('disconnect_accepted=' + $discReply.StartsWith('OK ').ToString().ToLowerInvariant())
    $disconnected = $false
    $discDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $discDeadline) {
        Start-Sleep -Seconds 1
        if ((Read-Status)['state'] -eq 'disconnected') { $disconnected = $true; break }
    }
    Add-Verdict ('disconnected=' + $disconnected.ToString().ToLowerInvariant())
    Add-Verdict ('wintun_adapter_gone=' + ((-not (Test-BeamAdapterUp)).ToString().ToLowerInvariant()))
    if (-not $disconnected) { throw 'never_disconnected' }
} catch {
    $failures++
    # Exception text is ours or the sanitized server reply; never secret-bearing.
    Write-Host ("live_e2e_error=" + $_.Exception.Message)
} finally {
    # ALWAYS restore runner connectivity: disconnect, uninstall, verify cleanup.
    try {
        $null = Invoke-Ipc -Line 'DISCONNECT'
    } catch {
        Write-Host 'final_disconnect_best_effort=false'
    }
    try {
        $uninstallPs1 = Join-Path $PackageDir 'install.ps1'
        if (Test-Path -LiteralPath $uninstallPs1) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstallPs1 -Uninstall -NonInteractive
        }
    } catch {
        Write-Host 'final_uninstall_best_effort=false'
    }
    $svcGone = ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue))
    Add-Verdict ('service_deleted=' + $svcGone.ToString().ToLowerInvariant())
    $dirGone = -not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'beam'))
    Add-Verdict ('install_dir_cleaned=' + $dirGone.ToString().ToLowerInvariant())
    Add-Verdict ('baseline_internet_restored=' + ((Get-PublicIpv4) -ne '').ToString().ToLowerInvariant())

    $overall = if ($failures -eq 0) { 'PASS' } else { 'FAIL' }
    $lines = @("windows-live-e2e: $overall") + @($verdicts)
    $summary = ($lines -join "`n")
    Write-Host $summary
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
    }
    if ($failures -gt 0) { $exitCode = 1 }
}

exit $exitCode
