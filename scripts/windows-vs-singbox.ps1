<#
.SYNOPSIS
    Fair head-to-head: native beam-client.exe vs sing-box.exe (TUN + VLESS-REALITY-Vision).

.DESCRIPTION
    Runs each client SEQUENTIALLY (never at the same time) against the same
    remote VPS from BEAM_LIVE_VLESS_LINK and measures the SAME metrics for both:
    connect_ms, ram_mb, https_ttfb_ms, download_mbps, dns_ms, egress_via_vps.

    Run 1 (beam-client.exe): packaged zip + install.ps1 + Named Pipe flow, same
    as scripts/windows-live-e2e.ps1 (async NamedPipeClientStream timeout,
    UTF8Encoding($false) so no BOM, child powershell.exe for install).
    Run 2 (sing-box.exe): parses the vless:// link in memory, writes a temporary
    TUN + VLESS-REALITY-Vision JSON config (auto_route, strict_route, mtu 1500,
    address schema of pinned sing-box 1.14.4), starts `sing-box.exe run -c`,
    polls egress until it equals the VPS IP (bounded 30s), measures the same
    metrics, then stops the process and deletes the temp config.

    Secret hygiene: the vless:// link, UUID, pbk, sid, sing-box config JSON, and
    VPS host/IP are NEVER printed and NEVER written to $GITHUB_STEP_SUMMARY.
    Only the secret-free metric table is emitted.
    PowerShell 5.1 and 7 compatible (no ??, no ternary, no ?. operators).

.EXAMPLE
    $env:BEAM_LIVE_VLESS_LINK = 'vless://...'
    pwsh -File scripts/windows-vs-singbox.ps1 -PackageDir C:\extracted-zip -SingboxExe C:\tools\sing-box.exe -CompareSingbox
#>

[CmdletBinding()]
param(
    [string]$PackageDir = (Join-Path $env:RUNNER_TEMP 'windows-live-e2e\extracted'),
    [string]$SingboxExe = '',
    [switch]$CompareSingbox
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'BeamClient'
$PipeName = 'beam-client-ipc'
$IpifyUrl = 'https://api.ipify.org'
$TtfbUrl = 'https://1.1.1.1/cdn-cgi/trace'
$DownUrl = 'https://speed.cloudflare.com/__down?bytes=25000000'

function Get-MedianDouble {
    param([double[]]$Values)
    $sorted = @($Values | Sort-Object)
    if ($sorted.Count -eq 0) { return 0 }
    $mid = [math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return $sorted[$mid] }
    return (($sorted[$mid - 1] + $sorted[$mid]) / 2.0)
}

function Invoke-Ipc {
    param(
        [Parameter(Mandatory = $true)][string]$Line,
        [int]$TimeoutMs = 5000
    )
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
        if (-not $writeTask.Wait($TimeoutMs)) { throw 'ipc_write_timeout' }
        $writer.Flush()
        $reader = New-Object System.IO.StreamReader($client, $utf8NoBom, $false, 1024, $true)
        $readTask = $reader.ReadLineAsync()
        if (-not $readTask.Wait($TimeoutMs)) { throw 'ipc_read_timeout' }
        $reply = $readTask.Result
        if ([string]::IsNullOrEmpty($reply)) { throw 'empty IPC reply' }
        return $reply
    } finally {
        $client.Dispose()
    }
}

function Read-BeamStatus {
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

function Get-ProcessRamMb {
    param([int]$ProcessId = 0, [string]$ProcessName = '')
    try {
        $proc = $null
        if ($ProcessId -gt 0) {
            $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        } elseif ($ProcessName -ne '') {
            $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if ($null -eq $proc) { return 'n/a' }
        $proc.Refresh()
        return ([math]::Round($proc.WorkingSet64 / 1048576.0, 1)).ToString('F1')
    } catch {
        return 'n/a'
    }
}

function Measure-HttpsTtfbMs {
    $samples = New-Object System.Collections.Generic.List[double]
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $out = & curl.exe -sS -o NUL -w '%{time_starttransfer}' --max-time 10 $TtfbUrl 2>$null
            $secs = 0.0
            if ([double]::TryParse(($out | Out-String).Trim(), [System.Globalization.NumberStyles]::Float, $inv, [ref]$secs)) {
                $samples.Add($secs * 1000.0)
            }
        } catch {
        }
    }
    if ($samples.Count -eq 0) { return 'fail' }
    return ([math]::Round((Get-MedianDouble -Values $samples.ToArray()), 0)).ToString('F0', $inv)
}

# Last bulk-download probe diagnostics (secret-free: exit code + HTTP code only).
$script:LastCurlExit = -1
$script:LastHttpCode = 'n/a'

function Measure-DownloadMbps {
    $script:LastCurlExit = -1
    $script:LastHttpCode = 'n/a'
    try {
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $out = & curl.exe -sS -o NUL -w '%{http_code} %{speed_download}' --max-time 30 $DownUrl 2>$null
        $script:LastCurlExit = $LASTEXITCODE
        $parts = @(((($out | Out-String).Trim()) -split '\s+'))
        if ($parts.Count -ge 1) { $script:LastHttpCode = $parts[0] }
        $speedText = ''
        if ($parts.Count -ge 2) { $speedText = $parts[1] }
        $bps = 0.0
        if (-not [double]::TryParse($speedText, [System.Globalization.NumberStyles]::Float, $inv, [ref]$bps)) { return 'fail' }
        if ($bps -le 0) { return 'fail' }
        if ($script:LastCurlExit -ne 0) { return 'fail' }
        return ([math]::Round($bps * 8.0 / 1000000.0, 1)).ToString('F1', $inv)
    } catch {
        return 'fail'
    }
}

function Measure-DnsMs {
    $samples = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt 3; $i++) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $null = Resolve-DnsName -Name 'example.com' -ErrorAction Stop
            $sw.Stop()
            $samples.Add($sw.Elapsed.TotalMilliseconds)
        } catch {
        }
    }
    if ($samples.Count -eq 0) { return 'fail' }
    return ([math]::Round((Get-MedianDouble -Values $samples.ToArray()), 0)).ToString('F0')
}

# Shared by both runs so the comparison stays strictly fair: same URL and
# same curl.exe flags for beam-client and sing-box.
function Measure-ConnectedMetrics {
    param([string]$VpsIpv4, [int]$RamPid = 0, [string]$RamName = '')
    $ram = Get-ProcessRamMb -ProcessId $RamPid -ProcessName $RamName
    $ttfb = Measure-HttpsTtfbMs
    $down = Measure-DownloadMbps
    $dns = Measure-DnsMs
    $egress = Get-PublicIpv4
    $via = (($egress -ne '') -and ($VpsIpv4 -ne '') -and ($egress -eq $VpsIpv4))
    return @{
        ram_mb = $ram; https_ttfb_ms = $ttfb; download_mbps = $down
        dns_ms = $dns; egress_via_vps = $via.ToString().ToLowerInvariant()
    }
}

function New-ResultRow {
    param([string]$Name)
    return @{
        name = $Name; connect_ms = 'fail'; ram_mb = 'n/a'; https_ttfb_ms = 'fail'
        download_mbps = 'fail'; dns_ms = 'fail'; egress_via_vps = 'false'; error = ''
    }
}

function Test-BeamAdapterUp {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Beam*' }
    return ($null -ne $adapters) -and
        (($adapters | Where-Object { $_.Status -eq 'Up' } | Measure-Object).Count -gt 0)
}

function Parse-VlessLink {
    param([string]$Link)
    # Supports pbk, sid, sni, fp, flow, security=reality, type=tcp, IPv4 or domain host.
    $m = [regex]::Match($Link, '^vless://(?<uuid>[^@]+)@(?<host>\[[^\]]+\]|[^:/?#]+)(:(?<port>\d+))?(\?(?<query>[^#]*))?')
    if (-not $m.Success) { throw 'vless_parse_failed' }
    $uuid = $m.Groups['uuid'].Value
    $serverHost = $m.Groups['host'].Value.Trim('[', ']')
    $port = 443
    if ($m.Groups['port'].Success) { $port = [int]$m.Groups['port'].Value }
    $q = @{}
    if ($m.Groups['query'].Success) {
        foreach ($pair in ($m.Groups['query'].Value -split '&')) {
            if ($pair -eq '') { continue }
            $kv = $pair -split '=', 2
            $k = [System.Net.WebUtility]::UrlDecode($kv[0]).ToLowerInvariant()
            $v = ''
            if ($kv.Count -eq 2) { $v = [System.Net.WebUtility]::UrlDecode($kv[1]) }
            $q[$k] = $v
        }
    }
    $security = 'reality'
    if ($q.ContainsKey('security')) { $security = $q['security'].ToLowerInvariant() }
    if ($security -ne 'reality') { throw 'vless_only_reality_supported' }
    $net = 'tcp'
    if ($q.ContainsKey('type')) { $net = $q['type'].ToLowerInvariant() }
    if ($net -ne 'tcp') { throw 'vless_only_tcp_supported' }
    $flow = 'xtls-rprx-vision'
    if ($q.ContainsKey('flow') -and ($q['flow'] -ne '')) { $flow = $q['flow'] }
    $fp = 'chrome'
    if ($q.ContainsKey('fp') -and ($q['fp'] -ne '')) { $fp = $q['fp'] }
    $sni = ''
    if ($q.ContainsKey('sni')) { $sni = $q['sni'] }
    $pbk = ''
    if ($q.ContainsKey('pbk')) { $pbk = $q['pbk'] }
    $sid = ''
    if ($q.ContainsKey('sid')) { $sid = $q['sid'] }
    if (($uuid -eq '') -or ($serverHost -eq '') -or ($sni -eq '') -or ($pbk -eq '')) {
        throw 'vless_missing_field'
    }
    return @{
        uuid = $uuid; host = $serverHost; port = $port; flow = $flow
        fp = $fp; sni = $sni; pbk = $pbk; sid = $sid
    }
}

function Run-BeamClient {
    param([string]$Link, [string]$VpsIpv4, [string]$PkgDir, [hashtable]$Row)
    try {
        $installPs1 = Join-Path $PkgDir 'install.ps1'
        if (-not (Test-Path -LiteralPath $installPs1)) { throw "install.ps1 not found under $PkgDir." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installPs1 -NoAutoStart -NoStart -NonInteractive 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "install_failed exit=$LASTEXITCODE" }
        $running = $false
        for ($i = 0; $i -lt 20; $i++) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (($null -ne $svc) -and ($svc.Status -eq 'Running')) { $running = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $running) { throw 'service_not_running' }
        $null = Read-BeamStatus
        $importReply = Invoke-Ipc -Line ("IMPORT_LINK " + $Link)
        if (-not $importReply.StartsWith('OK ')) { throw 'import_failed' }
        $t0 = [DateTime]::UtcNow
        $connectReply = Invoke-Ipc -Line 'CONNECT'
        if (-not $connectReply.StartsWith('OK ')) { throw 'connect_rejected' }
        $connected = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 2
            $st = Read-BeamStatus
            if ($st['state'] -eq 'connected') { $connected = $true; break }
            if ($st['state'] -eq 'error') { break }
        }
        if (-not $connected) { throw 'never_connected' }
        $Row['connect_ms'] = ([math]::Round(([DateTime]::UtcNow - $t0).TotalMilliseconds, 0)).ToString('F0', [System.Globalization.CultureInfo]::InvariantCulture)
        $metrics = Measure-ConnectedMetrics -VpsIpv4 $VpsIpv4 -RamName 'beam-client'
        foreach ($k in $metrics.Keys) { $Row[$k] = $metrics[$k] }
        if ($Row['download_mbps'] -eq 'fail') {
            # STATUS before DISCONNECT: drops are a sanitized secret-free token.
            $drops = 'none'
            try {
                $stDiag = Read-BeamStatus
                if (($stDiag['drops'] -ne $null) -and ($stDiag['drops'] -ne '')) { $drops = $stDiag['drops'] }
            } catch {
            }
            Write-Host ('download_diag curl_exit=' + $script:LastCurlExit + ' http_code=' + $script:LastHttpCode + ' beam_drops=' + $drops)
            throw 'download_failed'
        }
        if ($Row['egress_via_vps'] -ne 'true') { throw 'egress_not_via_vps' }
        $null = Invoke-Ipc -Line 'DISCONNECT'
    } catch {
        $Row['error'] = $_.Exception.Message
    } finally {
        try { $null = Invoke-Ipc -Line 'DISCONNECT' } catch {
        }
        try {
            $uninstallPs1 = Join-Path $PkgDir 'install.ps1'
            if (Test-Path -LiteralPath $uninstallPs1) {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstallPs1 -Uninstall -NonInteractive 2>&1 | Out-Host
            }
        } catch {
        }
    }
}

function Run-Singbox {
    param([object]$Parts, [string]$VpsIpv4, [string]$Exe, [hashtable]$Row)
    $cfgPath = ''
    $proc = $null
    try {
        if (($Exe -eq '') -or (-not (Test-Path -LiteralPath $Exe))) { throw 'singbox_exe_missing' }
        $cfg = @{
            log = @{ level = 'warn'; timestamp = $true }
            dns = @{
                servers = @(
                    @{
                        tag = 'remote-doh'; type = 'https'; server = '1.1.1.1'
                        server_port = 443; path = '/dns-query'; detour = 'proxy'
                    },
                    @{ tag = 'local-dns'; type = 'local'; detour = 'direct' }
                )
                final = 'remote-doh'
                strategy = 'ipv4_only'
            }
            inbounds = @(@{
                type = 'tun'; tag = 'tun-in'; interface_name = 'sbtun'
                address = @('172.19.1.1/30'); mtu = 1500
                auto_route = $true; strict_route = $true; stack = 'system'
            })
            outbounds = @(
                @{
                    type = 'vless'; tag = 'proxy'
                    server = $Parts.host; server_port = $Parts.port
                    uuid = $Parts.uuid; flow = $Parts.flow; packet_encoding = 'xudp'
                    tls = @{
                        enabled = $true; server_name = $Parts.sni
                        utls = @{ enabled = $true; fingerprint = $Parts.fp }
                        reality = @{
                            enabled = $true; public_key = $Parts.pbk; short_id = $Parts.sid
                        }
                    }
                },
                @{ type = 'direct'; tag = 'direct' }
            )
            route = @{
                auto_detect_interface = $true
                default_domain_resolver = 'local-dns'
                rules = @(
                    @{ action = 'sniff' },
                    @{ protocol = 'dns'; action = 'hijack-dns' }
                )
                final = 'proxy'
            }
        }
        # Config holds secrets: write to a temp file, never print it.
        $cfgPath = Join-Path ([System.IO.Path]::GetTempPath()) ('sb-vs-' + [System.Guid]::NewGuid().ToString('N') + '.json')
        ($cfg | ConvertTo-Json -Depth 10 -Compress) | Set-Content -LiteralPath $cfgPath -Encoding Ascii
        # Never start sing-box while beam-client is still installed/running.
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $svc) { throw 'beam_still_present' }
        $t0 = [DateTime]::UtcNow
        $proc = Start-Process -FilePath $Exe -ArgumentList @('run', '-c', $cfgPath) -NoNewWindow -PassThru
        $connected = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 2
            if (($proc.HasExited) -and ($proc.ExitCode -ne 0)) { throw 'singbox_exited' }
            $egress = Get-PublicIpv4
            if (($egress -ne '') -and ($VpsIpv4 -ne '') -and ($egress -eq $VpsIpv4)) {
                $connected = $true; break
            }
        }
        if (-not $connected) { throw 'singbox_never_connected' }
        $Row['connect_ms'] = ([math]::Round(([DateTime]::UtcNow - $t0).TotalMilliseconds, 0)).ToString('F0', [System.Globalization.CultureInfo]::InvariantCulture)
        $metrics = Measure-ConnectedMetrics -VpsIpv4 $VpsIpv4 -RamPid $proc.Id
        foreach ($k in $metrics.Keys) { $Row[$k] = $metrics[$k] }
        if ($Row['download_mbps'] -eq 'fail') {
            Write-Host ('download_diag curl_exit=' + $script:LastCurlExit + ' http_code=' + $script:LastHttpCode)
            throw 'download_failed'
        }
        if ($Row['egress_via_vps'] -ne 'true') { throw 'egress_not_via_vps' }
    } catch {
        $Row['error'] = $_.Exception.Message
    } finally {
        try {
            if (($null -ne $proc) -and (-not $proc.HasExited)) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                $null = $proc.WaitForExit(10000)
            }
        } catch {
        }
        try {
            Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {
        }
        try {
            if (($cfgPath -ne '') -and (Test-Path -LiteralPath $cfgPath)) {
                Remove-Item -LiteralPath $cfgPath -Force -ErrorAction SilentlyContinue
            }
        } catch {
        }
    }
}

$exitCode = 0
$beamRow = New-ResultRow -Name 'beam-client'
$sbRow = New-ResultRow -Name 'sing-box'
try {
    $link = $env:BEAM_LIVE_VLESS_LINK
    if ([string]::IsNullOrWhiteSpace($link)) { throw 'BEAM_LIVE_VLESS_LINK is empty or unset.' }
    if ($link -notmatch '^vless://') { throw 'BEAM_LIVE_VLESS_LINK does not start with vless://.' }

    $parts = Parse-VlessLink -Link $link
    $vpsHost = $parts.host
    # Mask every secret-bearing value before any check runs.
    if ($parts.uuid -ne '') { Write-Host ('::add-mask::' + $parts.uuid) }
    if ($parts.pbk -ne '') { Write-Host ('::add-mask::' + $parts.pbk) }
    if ($parts.sid -ne '') { Write-Host ('::add-mask::' + $parts.sid) }
    if ($vpsHost -ne '') { Write-Host ('::add-mask::' + $vpsHost) }
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
    if ($vpsIpv4 -ne '') { Write-Host ('::add-mask::' + $vpsIpv4) }

    $baseline = Get-PublicIpv4
    Write-Host ('baseline_egress_reachable=' + ($baseline -ne '').ToString().ToLowerInvariant())

    # Run 1: beam-client (its finally block uninstalls and restores baseline).
    Run-BeamClient -Link $link -VpsIpv4 $vpsIpv4 -PkgDir $PackageDir -Row $beamRow
    if ($beamRow['error'] -ne '') {
        Write-Host ('beam_error=' + $beamRow['error'])
    }
    # Confirm baseline internet is restored before touching sing-box.
    $restored = ((Get-PublicIpv4) -ne '')
    Write-Host ('baseline_restored_after_beam=' + $restored.ToString().ToLowerInvariant())
    if (-not $restored) { throw 'baseline_not_restored_after_beam' }

    if ($CompareSingbox -or ($SingboxExe -ne '')) {
        if ($SingboxExe -eq '') {
            $found = Get-Command 'sing-box.exe' -ErrorAction SilentlyContinue
            if ($null -ne $found) { $SingboxExe = $found.Source }
        }
        # Run 2: sing-box, strictly after beam cleanup (never concurrent).
        Run-Singbox -Parts $parts -VpsIpv4 $vpsIpv4 -Exe $SingboxExe -Row $sbRow
        if ($sbRow['error'] -ne '') {
            Write-Host ('singbox_error=' + $sbRow['error'])
        }
        $restored2 = ((Get-PublicIpv4) -ne '')
        Write-Host ('baseline_restored_after_singbox=' + $restored2.ToString().ToLowerInvariant())
        if (-not $restored2) { throw 'baseline_not_restored_after_singbox' }
    }

    if (($beamRow['error'] -ne '') -or (($CompareSingbox -or ($SingboxExe -ne '')) -and ($sbRow['error'] -ne ''))) {
        $exitCode = 1
    }
} catch {
    $exitCode = 1
    Write-Host ('vs_error=' + $_.Exception.Message)
} finally {
    # Secret-free comparison table only. Never log link, UUID, pbk, sid, config, host/IP.
    $lines = @(
        '| Metric | beam-client | sing-box |',
        '|---|---|---|',
        ('| connect_ms | ' + $beamRow['connect_ms'] + ' | ' + $sbRow['connect_ms'] + ' |'),
        ('| ram_mb | ' + $beamRow['ram_mb'] + ' | ' + $sbRow['ram_mb'] + ' |'),
        ('| https_ttfb_ms | ' + $beamRow['https_ttfb_ms'] + ' | ' + $sbRow['https_ttfb_ms'] + ' |'),
        ('| download_mbps | ' + $beamRow['download_mbps'] + ' | ' + $sbRow['download_mbps'] + ' |'),
        ('| dns_ms | ' + $beamRow['dns_ms'] + ' | ' + $sbRow['dns_ms'] + ' |'),
        ('| egress_via_vps | ' + $beamRow['egress_via_vps'] + ' | ' + $sbRow['egress_via_vps'] + ' |')
    )
    $summary = ($lines -join "`n")
    Write-Host $summary
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
    }
}

exit $exitCode
