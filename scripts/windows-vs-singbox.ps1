<#
.SYNOPSIS
    Fair head-to-head: native beam-client.exe vs sing-box.exe (TUN + VLESS-REALITY-Vision).

.DESCRIPTION
    Runs each client SEQUENTIALLY (never at the same time) against the same
    remote VPS from BEAM_LIVE_VLESS_LINK and measures the SAME metrics for both:
    connect_ms, ram_mb, https_ttfb_ms, download_mbps, dns_ms, egress_via_vps.

    Interleaved rounds (default 3): each round runs beam first, then sing-box,
    so a transient runner or network phase cannot favour one client. One noisy
    round cannot flip the conclusion: the table reports the median and the
    min/max range across rounds, plus per-round curl exit and HTTP codes.
    A per-round failure records 'fail' for that round and the run continues.

    Per round and per client: one 25 MB warm-up download is discarded, then a
    fixed 100 MB measured download reports Mbps. CPU seconds (process
    TotalProcessorTime delta over the measured round) separate a CPU-bound gap
    from a receive-window-bound gap. Beam drops come from the secret-free
    STATUS drops token ('none' when absent); sing-box reports 'n/a'.

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
    pwsh -File scripts/windows-vs-singbox.ps1 -PackageDir C:\extracted-zip -SingboxExe C:\tools\sing-box.exe -CompareSingbox -Rounds 3
#>

[CmdletBinding()]
param(
    [string]$PackageDir = (Join-Path $env:RUNNER_TEMP 'windows-live-e2e\extracted'),
    [string]$SingboxExe = '',
    [switch]$CompareSingbox,
    [int]$Rounds = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'BeamClient'
$PipeName = 'beam-client-ipc'
$IpifyUrl = 'https://api.ipify.org'
$TtfbUrl = 'https://1.1.1.1/cdn-cgi/trace'
$DownUrlWarm = 'https://speed.cloudflare.com/__down?bytes=25000000'
# Measured download is 4 chunks of the working 25 MB URL (100 MB total).
$DownChunks = 4
$DownChunkBytes = 25000000

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

function Get-ProcessCpuSeconds {
    param([int]$ProcessId = 0, [string]$ProcessName = '')
    try {
        $proc = $null
        if ($ProcessId -gt 0) {
            $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        } elseif ($ProcessName -ne '') {
            $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if ($null -eq $proc) { return -1.0 }
        $proc.Refresh()
        return $proc.TotalProcessorTime.TotalSeconds
    } catch {
        return -1.0
    }
}

function Get-BeamDropsToken {
    try {
        $st = Read-BeamStatus
        $drops = $st['drops']
        if (($null -ne $drops) -and ($drops -ne '')) { return [string]$drops }
        return 'none'
    } catch {
        # 'unknown' must not look like the clean 'none' token: a broken STATUS
        # reply would otherwise pass silently.
        return 'unknown'
    }
}

function Get-BeamRttMs {
    try {
        $st = Read-BeamStatus
        $rtt = $st['rtt_ms']
        if (($null -ne $rtt) -and ($rtt -ne '') -and ($rtt -ne 'none')) { return [string]$rtt }
        return 'n/a'
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
$script:LastMulti4CurlExit = -1
$script:LastMulti4HttpCode = 'n/a'

function Invoke-DownloadWarmup {
    # Discarded 25 MB request that warms the path before the measured one.
    # Never throws, never reports; bounded so a stall cannot hang the round.
    try {
        $null = & curl.exe -sS -o NUL -w '%{http_code}' --max-time 30 $DownUrlWarm 2>$null
    } catch {
    }
}

function Measure-DownloadMbps {
    $script:LastCurlExit = -1
    $script:LastHttpCode = 'n/a'
    try {
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        # One window over 4 chunks of the working 25 MB URL (100 MB total).
        # Any non-2xx code or non-zero exit fails the round.
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        for ($c = 0; $c -lt $DownChunks; $c++) {
            $out = & curl.exe -sS -o NUL -w '%{http_code}' --max-time 30 $DownUrlWarm 2>$null
            $script:LastCurlExit = $LASTEXITCODE
            $code = (($out | Out-String).Trim())
            $script:LastHttpCode = $code
            if ($LASTEXITCODE -ne 0) { $sw.Stop(); return 'fail' }
            if ($code -notmatch '^2') { $sw.Stop(); return 'fail' }
        }
        $sw.Stop()
        $secs = $sw.Elapsed.TotalSeconds
        if ($secs -le 0) { return 'fail' }
        $totalBytes = [double]$DownChunks * [double]$DownChunkBytes
        $mbps = $totalBytes * 8.0 / $secs / 1000000.0
        if ($mbps -le 0) { return 'fail' }
        return ([math]::Round($mbps, 1)).ToString('F1', $inv)
    } catch {
        return 'fail'
    }
}

function Measure-Multi4DownloadMbps {
    # Four concurrent 25 MB transfers (one curl.exe each), timed as one group.
    # Aggregate is 100 MB over wall time; any non-2xx or non-zero exit fails.
    $script:LastMulti4CurlExit = -1
    $script:LastMulti4HttpCode = 'n/a'
    $flows = 4
    $tmpFiles = @()
    $procs = @()
    try {
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        for ($i = 0; $i -lt $flows; $i++) {
            $tmpFiles += [System.IO.Path]::GetTempFileName()
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt $flows; $i++) {
            $p = Start-Process -FilePath 'curl.exe' -ArgumentList @('-sS', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '60', $DownUrlWarm) -NoNewWindow -PassThru -RedirectStandardOutput $tmpFiles[$i]
            $procs += $p
        }
        $allExited = $true
        foreach ($p in $procs) {
            try {
                $exited = $p.WaitForExit(65000)
                if (-not $exited) {
                    $allExited = $false
                    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {
                    }
                }
            } catch {
                $allExited = $false
            }
        }
        $sw.Stop()
        $worstExit = 0
        $worstHttp = '200'
        $sawHttpFail = $false
        $anyFail = (-not $allExited)
        for ($i = 0; $i -lt $flows; $i++) {
            $code = ''
            try { $code = ((Get-Content -LiteralPath $tmpFiles[$i] -Raw -ErrorAction SilentlyContinue | Out-String).Trim()) } catch { $code = '' }
            if ([string]::IsNullOrWhiteSpace($code)) { $code = 'n/a' }
            if ($code -notmatch '^2') {
                if (-not $sawHttpFail) { $worstHttp = $code }
                $sawHttpFail = $true
                $anyFail = $true
            } else {
                if (-not $sawHttpFail) { $worstHttp = $code }
            }
            $exit = -1
            try {
                if ($procs[$i].HasExited) { $exit = [int]$procs[$i].ExitCode } else { $exit = 124 }
            } catch { $exit = -1 }
            if ($exit -ne 0) {
                $anyFail = $true
                if ($worstExit -eq 0) { $worstExit = $exit }
                if (($exit -gt $worstExit) -and ($worstExit -ne 0)) { $worstExit = $exit }
            }
        }
        foreach ($t in $tmpFiles) {
            try { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } catch {
            }
        }
        if ((-not $allExited) -and ($worstExit -eq 0)) { $worstExit = 124 }
        $script:LastMulti4CurlExit = $worstExit
        $script:LastMulti4HttpCode = $worstHttp
        if ($anyFail) { return 'fail' }
        $secs = $sw.Elapsed.TotalSeconds
        if ($secs -le 0) { return 'fail' }
        $totalBytes = [double]$flows * [double]$DownChunkBytes
        $mbps = $totalBytes * 8.0 / $secs / 1000000.0
        if ($mbps -le 0) { return 'fail' }
        return ([math]::Round($mbps, 1)).ToString('F1', $inv)
    } catch {
        foreach ($t in $tmpFiles) {
            try { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } catch {
            }
        }
        try {
            foreach ($p in $procs) {
                try {
                    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
                } catch {
                }
            }
        } catch {
        }
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

# Shared by both runs so the comparison stays strictly fair: same warm-up,
# same URL and same curl.exe flags for beam-client and sing-box.
function Measure-ConnectedMetrics {
    param([string]$VpsIpv4, [int]$RamPid = 0, [string]$RamName = '')
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ram = Get-ProcessRamMb -ProcessId $RamPid -ProcessName $RamName
    $ttfb = Measure-HttpsTtfbMs
    $null = Invoke-DownloadWarmup
    # CPU seconds are sampled around the measured transfer only, so a slow
    # handshake or DNS query cannot be charged to the download path.
    $cpu0 = Get-ProcessCpuSeconds -ProcessId $RamPid -ProcessName $RamName
    $down = Measure-DownloadMbps
    $cpu1 = Get-ProcessCpuSeconds -ProcessId $RamPid -ProcessName $RamName
    $cpu = 'n/a'
    if (($cpu0 -ge 0) -and ($cpu1 -ge $cpu0)) {
        $cpu = ([math]::Round($cpu1 - $cpu0, 1)).ToString('F1', $inv)
    }
    $multi4 = Measure-Multi4DownloadMbps
    $multi4Exit = [string]$script:LastMulti4CurlExit
    $multi4Http = [string]$script:LastMulti4HttpCode
    $dns = Measure-DnsMs
    $egress = Get-PublicIpv4
    $via = (($egress -ne '') -and ($VpsIpv4 -ne '') -and ($egress -eq $VpsIpv4))
    return @{
        ram_mb = $ram; https_ttfb_ms = $ttfb; download_mbps = $down
        multi4_mbps = $multi4; multi4_curl_exit = $multi4Exit; multi4_http_code = $multi4Http
        dns_ms = $dns; cpu_s = $cpu; egress_via_vps = $via.ToString().ToLowerInvariant()
    }
}

function New-RoundRow {
    return @{
        connect_ms = 'fail'; ram_mb = 'n/a'; https_ttfb_ms = 'fail'
        download_mbps = 'fail'; multi4_mbps = 'fail'; dns_ms = 'fail'; egress_via_vps = 'false'
        cpu_s = 'n/a'; drops = 'none'; curl_exit = 'n/a'; http_code = 'n/a'
        multi4_curl_exit = 'n/a'; multi4_http_code = 'n/a'
        rtt_ms = 'n/a'; error = ''
    }
}

function Format-RoundLine {
    param([int]$Index, [int]$Total, [string]$Name, [hashtable]$Round)
    return ('round ' + $Index + '/' + $Total + ' ' + $Name +
        ': connect_ms=' + $Round['connect_ms'] +
        ' ram_mb=' + $Round['ram_mb'] +
        ' ttfb_ms=' + $Round['https_ttfb_ms'] +
        ' down_mbps=' + $Round['download_mbps'] +
        ' multi4_mbps=' + $Round['multi4_mbps'] +
        ' dns_ms=' + $Round['dns_ms'] +
        ' cpu_s=' + $Round['cpu_s'] +
        ' drops=' + $Round['drops'] +
        ' rtt_ms=' + $Round['rtt_ms'] +
        ' curl_exit=' + $Round['curl_exit'] +
        ' http=' + $Round['http_code'] +
        ' multi4_curl_exit=' + $Round['multi4_curl_exit'] +
        ' multi4_http=' + $Round['multi4_http_code'] +
        ' egress=' + $Round['egress_via_vps'] +
        ' err=' + $Round['error'])
}

function Format-AggCell {
    param([object[]]$Rows, [string]$Key, [int]$Decimals = 0)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $fmt = 'F' + $Decimals
    $vals = New-Object System.Collections.Generic.List[double]
    $total = 0
    if ($null -ne $Rows) {
        foreach ($r in $Rows) {
            if ($null -eq $r) { continue }
            $total++
            $s = ''
            if ($null -ne $r[$Key]) { $s = [string]$r[$Key] }
            $v = 0.0
            if (($s -ne '') -and ($s -ne 'fail') -and ($s -ne 'n/a')) {
                if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, $inv, [ref]$v)) {
                    $vals.Add($v)
                }
            }
        }
    }
    if ($vals.Count -eq 0) { return 'fail' }
    $arr = $vals.ToArray()
    $med = Get-MedianDouble -Values $arr
    $min = $arr[0]
    $max = $arr[0]
    foreach ($v in $arr) {
        if ($v -lt $min) { $min = $v }
        if ($v -gt $max) { $max = $v }
    }
    return ($med.ToString($fmt, $inv) + ' [' + $min.ToString($fmt, $inv) + '-' + $max.ToString($fmt, $inv) + '] (n=' + $vals.Count + '/' + $total + ')')
}

function Format-JoinCell {
    param([object[]]$Rows, [string]$Key)
    $items = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Rows) {
        foreach ($r in $Rows) {
            if ($null -eq $r) { continue }
            $s = 'n/a'
            if ($null -ne $r[$Key]) { $s = [string]$r[$Key] }
            if ($s -eq '') { $s = 'n/a' }
            $items.Add($s)
        }
    }
    if ($items.Count -eq 0) { return 'n/a' }
    return ([string]::Join(',', $items.ToArray()))
}

function Format-EgressCell {
    param([object[]]$Rows)
    $total = 0
    $ok = 0
    if ($null -ne $Rows) {
        foreach ($r in $Rows) {
            if ($null -eq $r) { continue }
            $total++
            if ($r['egress_via_vps'] -eq 'true') { $ok++ }
        }
    }
    if ($total -eq 0) { return 'n/a' }
    $label = 'false'
    if ($ok -eq $total) { $label = 'true' }
    if (($ok -gt 0) -and ($ok -lt $total)) { $label = 'mixed' }
    return ($label + ' (' + $ok + '/' + $total + ')')
}

function Format-RoundsCell {
    param([object[]]$Rows)
    $total = 0
    $ok = 0
    if ($null -ne $Rows) {
        foreach ($r in $Rows) {
            if ($null -eq $r) { continue }
            $total++
            if ($r['error'] -eq '') { $ok++ }
        }
    }
    return ($total.ToString([System.Globalization.CultureInfo]::InvariantCulture) + ' (ok ' + $ok + ')')
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

function Run-BeamRound {
    param([string]$Link, [string]$VpsIpv4, [string]$PkgDir, [hashtable]$Round, [int]$RoundIndex, [int]$RoundTotal)
    # 'unknown' until STATUS is read, so a round that throws early cannot look clean.
    $Round['drops'] = 'unknown'
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
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $Round['connect_ms'] = ([math]::Round(([DateTime]::UtcNow - $t0).TotalMilliseconds, 0)).ToString('F0', $inv)
        $metrics = Measure-ConnectedMetrics -VpsIpv4 $VpsIpv4 -RamName 'beam-client'
        foreach ($k in $metrics.Keys) { $Round[$k] = $metrics[$k] }
        $Round['curl_exit'] = [string]$script:LastCurlExit
        $Round['http_code'] = [string]$script:LastHttpCode
        # STATUS before DISCONNECT: drops are a sanitized secret-free token.
        $Round['drops'] = Get-BeamDropsToken
        $Round['rtt_ms'] = Get-BeamRttMs
        if ($Round['download_mbps'] -eq 'fail') { throw 'download_failed' }
        if ($Round['egress_via_vps'] -ne 'true') { throw 'egress_not_via_vps' }
        $null = Invoke-Ipc -Line 'DISCONNECT'
    } catch {
        $Round['error'] = $_.Exception.Message
    } finally {
        # One secret-free line per round so medians stay attributable.
        Write-Host (Format-RoundLine -Index $RoundIndex -Total $RoundTotal -Name 'beam' -Round $Round)
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

function Run-SingboxRound {
    param([object]$Parts, [string]$VpsIpv4, [string]$Exe, [hashtable]$Round, [int]$RoundIndex, [int]$RoundTotal)
    $Round['drops'] = 'n/a'
    $Round['rtt_ms'] = 'n/a'
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
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $Round['connect_ms'] = ([math]::Round(([DateTime]::UtcNow - $t0).TotalMilliseconds, 0)).ToString('F0', $inv)
        $metrics = Measure-ConnectedMetrics -VpsIpv4 $VpsIpv4 -RamPid $proc.Id
        foreach ($k in $metrics.Keys) { $Round[$k] = $metrics[$k] }
        $Round['curl_exit'] = [string]$script:LastCurlExit
        $Round['http_code'] = [string]$script:LastHttpCode
        if ($Round['download_mbps'] -eq 'fail') { throw 'download_failed' }
        if ($Round['egress_via_vps'] -ne 'true') { throw 'egress_not_via_vps' }
    } catch {
        $Round['error'] = $_.Exception.Message
    } finally {
        # One secret-free line per round so medians stay attributable.
        Write-Host (Format-RoundLine -Index $RoundIndex -Total $RoundTotal -Name 'singbox' -Round $Round)
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
$beamRounds = @()
$sbRounds = @()
$runSingbox = $false
try {
    $link = $env:BEAM_LIVE_VLESS_LINK
    if ([string]::IsNullOrWhiteSpace($link)) { throw 'BEAM_LIVE_VLESS_LINK is empty or unset.' }
    if ($link -notmatch '^vless://') { throw 'BEAM_LIVE_VLESS_LINK does not start with vless://.' }

    # Clamp rounds so bounded per-round waits stay inside the job timeout
    # (3 rounds x 2 clients x ~200 s worst case fits the 45-minute job limit).
    if ($Rounds -lt 1) { $Rounds = 1 }
    if ($Rounds -gt 3) { $Rounds = 3 }

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

    $runSingbox = ($CompareSingbox -or ($SingboxExe -ne ''))
    if ($runSingbox -and ($SingboxExe -eq '')) {
        $found = Get-Command 'sing-box.exe' -ErrorAction SilentlyContinue
        if ($null -ne $found) { $SingboxExe = $found.Source }
    }

    # Interleaved rounds: beam then sing-box each round, never concurrent.
    # A per-round failure records 'fail' for that round and the run continues.
    for ($ri = 1; $ri -le $Rounds; $ri++) {
        $bRound = New-RoundRow
        Run-BeamRound -Link $link -VpsIpv4 $vpsIpv4 -PkgDir $PackageDir -Round $bRound -RoundIndex $ri -RoundTotal $Rounds
        $beamRounds += $bRound
        if ($bRound['error'] -ne '') {
            Write-Host ('beam_round' + $ri + '_error=' + $bRound['error'])
        }
        # Confirm baseline internet is restored before touching sing-box.
        $restored = ((Get-PublicIpv4) -ne '')
        Write-Host ('baseline_restored_after_beam_r' + $ri + '=' + $restored.ToString().ToLowerInvariant())
        if (-not $restored) { throw 'baseline_not_restored_after_beam' }

        if ($runSingbox) {
            $sRound = New-RoundRow
            Run-SingboxRound -Parts $parts -VpsIpv4 $vpsIpv4 -Exe $SingboxExe -Round $sRound -RoundIndex $ri -RoundTotal $Rounds
            $sbRounds += $sRound
            if ($sRound['error'] -ne '') {
                Write-Host ('singbox_round' + $ri + '_error=' + $sRound['error'])
            }
            $restored2 = ((Get-PublicIpv4) -ne '')
            Write-Host ('baseline_restored_after_singbox_r' + $ri + '=' + $restored2.ToString().ToLowerInvariant())
            if (-not $restored2) { throw 'baseline_not_restored_after_singbox' }
        }
    }

    $anyError = $false
    foreach ($r in $beamRounds) {
        if ($r['error'] -ne '') { $anyError = $true }
    }
    if ($runSingbox) {
        foreach ($r in $sbRounds) {
            if ($r['error'] -ne '') { $anyError = $true }
        }
    }
    if ($anyError) {
        $exitCode = 1
    }
} catch {
    $exitCode = 1
    Write-Host ('vs_error=' + $_.Exception.Message)
} finally {
    # Secret-free comparison table only. Never log link, UUID, pbk, sid, config, host/IP.
    # Numeric cells show median [min-max] (n=ok/total) so one noisy round
    # cannot flip the conclusion; round counts make that visible.
    $lines = @(
        '| Metric | beam-client | sing-box |',
        '|---|---|---|',
        ('| connect_ms | ' + (Format-AggCell -Rows $beamRounds -Key 'connect_ms' -Decimals 0) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'connect_ms' -Decimals 0) + ' |'),
        ('| ram_mb | ' + (Format-AggCell -Rows $beamRounds -Key 'ram_mb' -Decimals 1) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'ram_mb' -Decimals 1) + ' |'),
        ('| https_ttfb_ms | ' + (Format-AggCell -Rows $beamRounds -Key 'https_ttfb_ms' -Decimals 0) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'https_ttfb_ms' -Decimals 0) + ' |'),
        ('| download_mbps | ' + (Format-AggCell -Rows $beamRounds -Key 'download_mbps' -Decimals 1) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'download_mbps' -Decimals 1) + ' |'),
        ('| multi4_mbps | ' + (Format-AggCell -Rows $beamRounds -Key 'multi4_mbps' -Decimals 1) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'multi4_mbps' -Decimals 1) + ' |'),
        ('| dns_ms | ' + (Format-AggCell -Rows $beamRounds -Key 'dns_ms' -Decimals 0) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'dns_ms' -Decimals 0) + ' |'),
        ('| cpu_s | ' + (Format-AggCell -Rows $beamRounds -Key 'cpu_s' -Decimals 1) + ' | ' + (Format-AggCell -Rows $sbRounds -Key 'cpu_s' -Decimals 1) + ' |'),
        ('| drops | ' + (Format-JoinCell -Rows $beamRounds -Key 'drops') + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'drops') + ' |'),
        ('| rtt_ms | ' + (Format-AggCell -Rows $beamRounds -Key 'rtt_ms' -Decimals 0) + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'rtt_ms') + ' |'),
        ('| download_curl_exit | ' + (Format-JoinCell -Rows $beamRounds -Key 'curl_exit') + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'curl_exit') + ' |'),
        ('| download_http_code | ' + (Format-JoinCell -Rows $beamRounds -Key 'http_code') + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'http_code') + ' |'),
        ('| multi4_curl_exit | ' + (Format-JoinCell -Rows $beamRounds -Key 'multi4_curl_exit') + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'multi4_curl_exit') + ' |'),
        ('| multi4_http_code | ' + (Format-JoinCell -Rows $beamRounds -Key 'multi4_http_code') + ' | ' + (Format-JoinCell -Rows $sbRounds -Key 'multi4_http_code') + ' |'),
        ('| egress_via_vps | ' + (Format-EgressCell -Rows $beamRounds) + ' | ' + (Format-EgressCell -Rows $sbRounds) + ' |'),
        ('| rounds | ' + (Format-RoundsCell -Rows $beamRounds) + ' | ' + (Format-RoundsCell -Rows $sbRounds) + ' |')
    )
    $summary = ($lines -join "`n")
    Write-Host $summary
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
    }
}

exit $exitCode
