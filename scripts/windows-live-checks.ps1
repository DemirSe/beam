<#
.SYNOPSIS
    Live behavioral verification for the native Windows client (Phase 6).

.DESCRIPTION
    Full lifecycle around five fail-closed behavioral checks, run while the
    packaged client from scripts/release-windows-tray.sh is installed and
    connected to the VPS from BEAM_LIVE_VLESS_LINK:
      route_fail_closed, dns_leak, ipv6_egress, service_restart, crash_recovery.

    Each check prints exactly one line:
      check=<name> result=pass|fail|skip detail=<token>
    where <token> carries no secret material (no link, UUID, pbk, sid,
    VPS host/IP, or config contents). A skip means CI could not reach the
    precondition (for example no Beam adapter because CONNECT never
    succeeded); a skip never fails the run by itself. Any fail, or any
    fatal flow error, exits non-zero after the finally block restores
    runner connectivity (disconnect, uninstall, bounded baseline wait).

    Secret hygiene: the link value is read only from
    $env:BEAM_LIVE_VLESS_LINK into local variables, masked with
    ::add-mask:: before any check runs, and never printed.
    PowerShell 5.1 and 7 compatible. ASCII only. Bounded waits only.

.EXAMPLE
    $env:BEAM_LIVE_VLESS_LINK = 'vless://...'
    pwsh -NoProfile -File scripts/windows-live-checks.ps1 -PackageDir C:\extracted-zip
#>

[CmdletBinding()]
param(
    [string]$PackageDir = (Join-Path $env:RUNNER_TEMP 'windows-live-e2e\extracted'),
    [int]$ConnectTimeoutSec = 30,
    [int]$CheckTimeoutSec = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'BeamClient'
$PipeName = 'beam-client-ipc'
$IpifyUrl = 'https://api.ipify.org'
$DualStackName = 'example.com'
$HttpsProbeUrl = 'https://example.com'

$script:VpsIpv4 = ''
$script:CheckTimeoutSec = $CheckTimeoutSec
# Positive control for the DNS leak check, keyed "<ifIndex>|<target>" and
# measured before the tunnel is up. Only controlled tuples can prove a block.
$script:ControlResults = @{}
# Values that must never reach the step log or the failure artifact.
$script:RedactList = @()
$script:checksPassed = 0

$checkLines = New-Object System.Collections.Generic.List[string]
$script:checksFailed = 0
$fatalError = ''
$exitCode = 0

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Result,
        [Parameter(Mandatory = $true)][string]$Detail
    )
    # Detail tokens are fixed ASCII slugs; never pass addresses or secrets here.
    $line = 'check=' + $Name + ' result=' + $Result + ' detail=' + $Detail
    $checkLines.Add($line)
    Write-Host $line
    if ($Result -eq 'fail') { $script:checksFailed++ }
    if ($Result -eq 'pass') { $script:checksPassed++ }
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

function Get-BeamIfIndex {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    foreach ($a in $adapters) {
        if ($a.Name -like 'Beam*') { return [int]$a.InterfaceIndex }
    }
    return -1
}

function Ensure-BoundDnsType {
    $existing = ([System.Management.Automation.PSTypeName]'BeamBoundDns').Type
    if ($null -ne $existing) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
public static class BeamBoundDns
{
    // Tri-state plus: 1 = the queried server answered on the wire (a leak),
    // 0 = no reply inside the timeout (blocked), 2 = an answer arrived from a
    // different peer, so the socket was not pinned, 3 = stray/unrelated
    // datagram, -1 = the probe itself could not run.
    public static int TryBoundQuery(string serverIp, int ifIndex, string localIp, string name, int timeoutMs)
    {
        Socket sock = null;
        try
        {
            if (serverIp == null) { return -1; }
            if (name == null) { return -1; }
            if (ifIndex < 0) { return -1; }
            if (timeoutMs < 500) { timeoutMs = 500; }
            if (timeoutMs > 10000) { timeoutMs = 10000; }
            IPAddress server = null;
            try { server = IPAddress.Parse(serverIp); }
            catch { return -1; }
            if (server.AddressFamily != AddressFamily.InterNetwork) { return -1; }
            byte[] query = BuildQuery(name, 0x4242);
            if (query == null) { return -1; }
            IPEndPoint remote = new IPEndPoint(server, 53);
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            // IP_UNICAST_IF takes the interface index in network byte order.
            int idxNet = IPAddress.HostToNetworkOrder(ifIndex);
            try { sock.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, idxNet); }
            catch { return -1; }
            // Bind the physical source address too, so the packet cannot be
            // routed into the WinTun split route.
            if ((localIp != null) && (localIp.Length > 0))
            {
                try
                {
                    IPAddress local = IPAddress.Parse(localIp);
                    if (local.AddressFamily == AddressFamily.InterNetwork)
                    {
                        sock.Bind(new IPEndPoint(local, 0));
                    }
                }
                catch { return -1; }
            }
            sock.SendTimeout = timeoutMs;
            sock.ReceiveTimeout = timeoutMs;
            try { sock.SendTo(query, remote); }
            catch { return -1; }
            bool readable = false;
            try { readable = sock.Poll(timeoutMs * 1000, SelectMode.SelectRead); }
            catch { return -1; }
            if (readable == false) { return 0; }
            byte[] buf = new byte[512];
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            int n = 0;
            // An ICMP rejection is only possible after the query left the host,
            // so a receive error still proves the packet reached the wire.
            try { n = sock.ReceiveFrom(buf, ref from); }
            catch (SocketException se)
            {
                // Only an ICMP rejection proves the query left the host; any
                // other socket error means the probe tells us nothing.
                if (se.SocketErrorCode == SocketError.ConnectionReset) { return 1; }
                return -1;
            }
            catch { return -1; }
            if (n < 12) { return 3; }
            // Only a reply carrying our transaction ID and question section
            // counts; anything else is a stray datagram, not an answer.
            if (buf[0] != 0x42) { return 3; }
            if (buf[1] != 0x42) { return 3; }
            if (n < query.Length) { return 3; }
            int k = 12;
            while (k < query.Length)
            {
                if (buf[k] != query[k]) { return 3; }
                k = k + 1;
            }
            IPEndPoint answerFrom = from as IPEndPoint;
            if (answerFrom == null) { return 1; }
            // Same peer means the packet left the physical interface: a leak.
            // A different peer means the socket was not pinned as requested.
            if (answerFrom.Address.Equals(server)) { return 1; }
            return 2;
        }
        catch { return -1; }
        finally
        {
            if (sock != null)
            {
                try { sock.Close(); }
                catch { }
            }
        }
    }
    private static byte[] BuildQuery(string name, int id)
    {
        try
        {
            if (name == null) { return null; }
            string trimmed = name.Trim();
            if (trimmed.Length == 0) { return null; }
            if (trimmed.EndsWith(".")) { trimmed = trimmed.Substring(0, trimmed.Length - 1); }
            string[] labels = trimmed.Split('.');
            if (labels.Length == 0) { return null; }
            byte[] tmp = new byte[512];
            tmp[0] = (byte)((id >> 8) & 0xFF);
            tmp[1] = (byte)(id & 0xFF);
            tmp[2] = 0x01;
            tmp[3] = 0x00;
            tmp[4] = 0x00;
            tmp[5] = 0x01;
            tmp[6] = 0x00;
            tmp[7] = 0x00;
            tmp[8] = 0x00;
            tmp[9] = 0x00;
            tmp[10] = 0x00;
            tmp[11] = 0x00;
            int pos = 12;
            foreach (string lab in labels)
            {
                if (lab == null) { return null; }
                if (lab.Length == 0) { return null; }
                if (lab.Length > 63) { return null; }
                byte[] lb = Encoding.ASCII.GetBytes(lab);
                if (pos + 1 + lb.Length + 5 >= tmp.Length) { return null; }
                tmp[pos] = (byte)lb.Length;
                pos = pos + 1;
                int i = 0;
                while (i < lb.Length)
                {
                    tmp[pos] = lb[i];
                    pos = pos + 1;
                    i = i + 1;
                }
            }
            tmp[pos] = 0x00;
            pos = pos + 1;
            tmp[pos] = 0x00;
            tmp[pos + 1] = 0x01;
            tmp[pos + 2] = 0x00;
            tmp[pos + 3] = 0x01;
            pos = pos + 4;
            byte[] outBuf = new byte[pos];
            int j = 0;
            while (j < pos)
            {
                outBuf[j] = tmp[j];
                j = j + 1;
            }
            return outBuf;
        }
        catch { return null; }
    }
}
'@
}

function Test-BeamAdapterUp {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    foreach ($a in $adapters) {
        if (($a.Name -like 'Beam*') -and ($a.Status -eq 'Up')) { return $true }
    }
    return $false
}

function Test-ConnectedState {
    try {
        $st = Read-Status
        if ($st['state'] -eq 'connected') { return $true }
    } catch {
    }
    return $false
}

function Wait-Connected {
    param([int]$TimeoutSec = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
        try {
            $st = Read-Status
            if ($st['state'] -eq 'connected') { return $true }
            if ($st['state'] -eq 'error') { return $false }
        } catch {
        }
    }
    return $false
}

function Test-RouteFailClosed {
    if (-not (Test-ConnectedState)) {
        Add-Check 'route_fail_closed' 'skip' 'not_connected'
        return
    }
    $beamIf = Get-BeamIfIndex
    if ($beamIf -lt 0) {
        Add-Check 'route_fail_closed' 'skip' 'no_beam_adapter'
        return
    }
    if ($null -eq (Get-Command Find-NetRoute -ErrorAction SilentlyContinue)) {
        Add-Check 'route_fail_closed' 'skip' 'no_find_netroute'
        return
    }
    try {
        $hasLow = $false
        $hasHigh = $false
        $dupOnPhysical = $false
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($r in $routes) {
            $prefix = $r.DestinationPrefix
            if (($prefix -eq '0.0.0.0/1') -or ($prefix -eq '128.0.0.0/1')) {
                if ([int]$r.InterfaceIndex -eq $beamIf) {
                    if ($prefix -eq '0.0.0.0/1') { $hasLow = $true }
                    if ($prefix -eq '128.0.0.0/1') { $hasHigh = $true }
                } else {
                    $dupOnPhysical = $true
                }
            }
        }
        if (-not $hasLow) {
            Add-Check 'route_fail_closed' 'fail' 'missing_0_0_0_0_1'
            return
        }
        if (-not $hasHigh) {
            Add-Check 'route_fail_closed' 'fail' 'missing_128_0_0_1'
            return
        }
        if ($dupOnPhysical) {
            Add-Check 'route_fail_closed' 'fail' 'duplicate_on_physical'
            return
        }
        $hasLowV6 = $false
        $hasHighV6 = $false
        $routesV6 = Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue
        foreach ($r in $routesV6) {
            $prefix = $r.DestinationPrefix
            if (($prefix -eq '::/1') -or ($prefix -eq '8000::/1')) {
                if ([int]$r.InterfaceIndex -eq $beamIf) {
                    if ($prefix -eq '::/1') { $hasLowV6 = $true }
                    if ($prefix -eq '8000::/1') { $hasHighV6 = $true }
                } else {
                    $dupOnPhysical = $true
                }
            }
        }
        if ($dupOnPhysical) {
            Add-Check 'route_fail_closed' 'fail' 'ipv6_duplicate_on_physical'
            return
        }
        if (-not ($hasLowV6 -and $hasHighV6)) {
            Add-Check 'route_fail_closed' 'fail' 'missing_ipv6_split'
            return
        }
        if ($script:VpsIpv4 -eq '') {
            Add-Check 'route_fail_closed' 'skip' 'no_vps_ip'
            return
        }
        $found = $null
        try {
            $found = Find-NetRoute -RemoteIPAddress $script:VpsIpv4 -ErrorAction Stop
        } catch {
            Add-Check 'route_fail_closed' 'fail' 'bypass_missing'
            return
        }
        $onTunnel = $false
        $viaPhysical = $false
        foreach ($r in $found) {
            if ([int]$r.InterfaceIndex -eq $beamIf) {
                $onTunnel = $true
            } else {
                $viaPhysical = $true
            }
        }
        if ($onTunnel) {
            Add-Check 'route_fail_closed' 'fail' 'bypass_on_tunnel'
            return
        }
        if (-not $viaPhysical) {
            Add-Check 'route_fail_closed' 'fail' 'bypass_missing'
            return
        }
        Add-Check 'route_fail_closed' 'pass' 'ok'
    } catch {
        Add-Check 'route_fail_closed' 'fail' 'check_error'
    }
}

function Get-DnsProbePlan {
    # Physical resolvers to probe: one entry per (adapter, server). The probe
    # target is a public resolver that the client does NOT permit, so an answer
    # there means plaintext DNS escaped the tunnel.
    param([int]$BeamIf = -1)
    $plan = @()
    try {
        foreach ($na in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
            if ($na.Name -like 'Beam*') { continue }
            if ($na.Status -ne 'Up') { continue }
            $idx = -1
            try { $idx = [int]$na.ifIndex } catch { continue }
            if (($idx -lt 0) -or ($idx -eq $BeamIf)) { continue }
            $localIp = ''
            foreach ($a in @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                if (-not [string]::IsNullOrWhiteSpace($a.IPAddress)) { $localIp = [string]$a.IPAddress; break }
            }
            if ($localIp -eq '') { continue }
            $servers = @()
            foreach ($o in @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                foreach ($s in @($o.ServerAddresses)) {
                    if ([string]::IsNullOrWhiteSpace($s)) { continue }
                    if ($s -like '127.*') { continue }
                    if ($servers -contains $s) { continue }
                    $servers += $s
                }
            }
            if ($servers.Count -eq 0) { continue }
            $plan += @{ IfIndex = $idx; LocalIp = $localIp; Server = $servers[0] }
        }
    } catch {
        return @()
    }
    return $plan
}

function Test-DnsLeak {
    if (-not (Test-ConnectedState)) {
        Add-Check 'dns_leak' 'skip' 'not_connected'
        return
    }
    $beamIf = Get-BeamIfIndex
    if ($beamIf -lt 0) {
        Add-Check 'dns_leak' 'skip' 'no_beam_adapter'
        return
    }
    try {
        $plan = @(Get-DnsProbePlan -BeamIf $beamIf)
        Write-Host ('physical_dns_count=' + $plan.Count)
        if ($plan.Count -eq 0) {
            Add-Check 'dns_leak' 'skip' 'no_physical_dns'
            return
        }
        Ensure-BoundDnsType
        # The client deliberately permits plaintext DNS to the pre-VPN resolver
        # (`permit_cidrs` includes `local_dns_ip`) so bypass suffixes still
        # resolve, so that server is not a leak signal. Any *other* port-53
        # destination must be blocked, which is what this check asserts.
        $publicTargets = @('1.1.1.1', '8.8.8.8')
        $deadline = [DateTime]::UtcNow.AddSeconds($script:CheckTimeoutSec)
        $leaked = $false
        $unpinned = 0
        $blocked = 0
        $probeErrors = 0
        $controlled = 0
        $localPermitAnswered = $false
        foreach ($entry in $plan) {
            if ([DateTime]::UtcNow -ge $deadline) { break }
            try {
                # Informational: the permitted resolver should still answer.
                $rcPermit = [BeamBoundDns]::TryBoundQuery([string]$entry['Server'], [int]$entry['IfIndex'], [string]$entry['LocalIp'], $DualStackName, 3000)
                if ($rcPermit -eq 1) { $localPermitAnswered = $true }
            } catch {
            }
            foreach ($target in $publicTargets) {
                if ([DateTime]::UtcNow -ge $deadline) { break }
                $key = ([string]$entry['IfIndex']) + '|' + $target
                # Only interpret a tuple whose pre-connect control answered.
                if (-not $script:ControlResults.ContainsKey($key)) { $probeErrors = $probeErrors + 1; continue }
                if (-not [bool]$script:ControlResults[$key]) { $probeErrors = $probeErrors + 1; continue }
                $controlled = $controlled + 1
                try {
                    # Strictly interface-bound UDP: IP_UNICAST_IF (31) pins the
                    # query to the physical NIC so WinTun split routes cannot
                    # answer it from inside the tunnel.
                    $rc = [BeamBoundDns]::TryBoundQuery($target, [int]$entry['IfIndex'], [string]$entry['LocalIp'], $DualStackName, 3000)
                    if ($rc -eq 1) { $leaked = $true; break }
                    if ($rc -eq 2) { $unpinned = $unpinned + 1 }
                    elseif ($rc -eq 0) { $blocked = $blocked + 1 }
                    else { $probeErrors = $probeErrors + 1 }
                } catch {
                    $probeErrors = $probeErrors + 1
                }
            }
            if ($leaked) { break }
        }
        Write-Host ('local_dns_permit_answered=' + $localPermitAnswered.ToString().ToLowerInvariant())
        Write-Host ('dns_probe_controlled=' + $controlled + ' blocked=' + $blocked + ' unpinned=' + $unpinned + ' errors=' + $probeErrors)
        if ($leaked) {
            Add-Check 'dns_leak' 'fail' 'public_dns_answered'
            return
        }
        if ($controlled -eq 0) {
            Add-Check 'dns_leak' 'skip' 'control_probe_failed'
            return
        }
        # A probe that could not run proves nothing: never report it as blocked.
        if ($blocked -eq 0) {
            if ($unpinned -gt 0) { Add-Check 'dns_leak' 'skip' 'probe_not_pinned'; return }
            Add-Check 'dns_leak' 'skip' 'bound_probe_error'
            return
        }
        try {
            $tunnel = Resolve-DnsName -Name $DualStackName -ErrorAction Stop
            if ($null -eq $tunnel) {
                Add-Check 'dns_leak' 'fail' 'tunnel_dns_empty'
                return
            }
        } catch {
            Add-Check 'dns_leak' 'fail' 'tunnel_dns_failed'
            return
        }
        Add-Check 'dns_leak' 'pass' 'public_dns_blocked'
    } catch {
        Add-Check 'dns_leak' 'fail' 'check_error'
    }
}

function Test-Ipv6Egress {
    if (-not (Test-ConnectedState)) {
        Add-Check 'ipv6_egress' 'skip' 'not_connected'
        return
    }
    $beamIf = Get-BeamIfIndex
    if ($beamIf -lt 0) {
        Add-Check 'ipv6_egress' 'skip' 'no_beam_adapter'
        return
    }
    try {
        $v6addrs = Get-NetIPAddress -InterfaceIndex $beamIf -AddressFamily IPv6 -ErrorAction SilentlyContinue
        $list = @($v6addrs)
        if (($null -eq $v6addrs) -or ($list.Count -eq 0)) {
            Add-Check 'ipv6_egress' 'skip' 'ipv6_disabled_on_beam'
            return
        }
        # The client assigns fd00:be:a::1/126 (inside fd00:be:a::/126) to the
        # tunnel itself, so that ULA is expected and is not a leak.
        $tunNet = ([System.Net.IPAddress]::Parse('fd00:be:a::')).GetAddressBytes()
        $hasTunUla = $false
        $hasGlobal = $false
        $hasUnexpected = $false
        foreach ($a in $list) {
            $ip = ''
            try { $ip = [string]$a.IPAddress } catch { continue }
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }
            $pct = $ip.IndexOf('%')
            if ($pct -ge 0) { $ip = $ip.Substring(0, $pct) }
            $low = $ip.ToLowerInvariant()
            if (($low -eq '::1') -or ($low -eq '::')) { continue }
            if ($low.StartsWith('ff')) { continue }
            $first = ($low -split ':')[0]
            $firstVal = -1
            try { $firstVal = [System.Convert]::ToInt32($first, 16) } catch { $firstVal = -1 }
            if (($firstVal -ge 0xfe80) -and ($firstVal -le 0xfebf)) { continue }
            $bytes = $null
            try { $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes() } catch { $hasUnexpected = $true; break }
            if (($null -eq $bytes) -or ($bytes.Length -ne 16)) { $hasUnexpected = $true; break }
            $inTun = $true
            for ($i = 0; $i -lt 15; $i++) {
                if ($bytes[$i] -ne $tunNet[$i]) { $inTun = $false; break }
            }
            if ($inTun) {
                if ((($bytes[15] -band 0xFC) -ne (($tunNet[15]) -band 0xFC))) { $inTun = $false }
            }
            if ($inTun) { $hasTunUla = $true; continue }
            $b0 = [int]$bytes[0]
            if ((($b0 -band 0xE0) -eq 0x20)) { $hasGlobal = $true; break }
            $hasUnexpected = $true
            break
        }
        if ($hasGlobal) {
            Add-Check 'ipv6_egress' 'fail' 'ipv6_global_on_beam'
            return
        }
        if ($hasUnexpected) {
            Add-Check 'ipv6_egress' 'fail' 'ipv6_unexpected_addr'
            return
        }
        if ($null -eq (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            Add-Check 'ipv6_egress' 'skip' 'no_curl'
            return
        }
        try {
            $null = & curl.exe -6 -sS -o NUL --max-time 10 $HttpsProbeUrl 2>$null
        } catch {
        }
        if ($LASTEXITCODE -eq 0) {
            Add-Check 'ipv6_egress' 'fail' 'ipv6_egress_open'
            return
        }
        if ($hasTunUla) {
            Add-Check 'ipv6_egress' 'pass' 'ula_only'
            return
        }
        Add-Check 'ipv6_egress' 'pass' 'ok'
    } catch {
        Add-Check 'ipv6_egress' 'fail' 'check_error'
    }
}

function Test-ServiceRestart {
    if (-not (Test-ConnectedState)) {
        Add-Check 'service_restart' 'skip' 'not_connected'
        return
    }
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Add-Check 'service_restart' 'skip' 'no_service'
        return
    }
    if ($script:VpsIpv4 -eq '') {
        Add-Check 'service_restart' 'skip' 'no_vps_ip'
        return
    }
    try {
        try {
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
        } catch {
            Add-Check 'service_restart' 'fail' 'restart_failed'
            return
        }
        $deadline = [DateTime]::UtcNow.AddSeconds($script:CheckTimeoutSec)
        $connected = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 2
            # No manual CONNECT nudge: `tun.auto_connect` is the property under
            # test, so a service that restarts idle must fail this check.
            try {
                $st = Read-Status
                if ($st['state'] -eq 'connected') { $connected = $true; break }
            } catch {
            }
        }
        if (-not $connected) {
            Add-Check 'service_restart' 'fail' 'not_reconnected'
            return
        }
        $egress = Get-PublicIpv4
        if ($egress -eq '') {
            Add-Check 'service_restart' 'fail' 'egress_unreachable'
            return
        }
        if ($egress -ne $script:VpsIpv4) {
            Add-Check 'service_restart' 'fail' 'egress_not_vps'
            return
        }
        Add-Check 'service_restart' 'pass' 'ok'
    } catch {
        Add-Check 'service_restart' 'fail' 'check_error'
    }
}

function Test-CrashRecovery {
    if (-not (Test-ConnectedState)) {
        Add-Check 'crash_recovery' 'skip' 'not_connected'
        return
    }
    $procs = Get-Process -Name 'beam-client' -ErrorAction SilentlyContinue
    $foundProc = $false
    foreach ($p in $procs) { $foundProc = $true; break }
    if (-not $foundProc) {
        Add-Check 'crash_recovery' 'skip' 'no_process'
        return
    }
    try {
        foreach ($p in $procs) {
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
            } catch {
            }
        }
        # Crash safety means the host is never left bricked: either the dynamic
        # WFP filters died with the process (baseline egress) or the service
        # restarted and auto-connected again. Both prove the property, so this
        # check does not race the SCM recovery/auto_connect path.
        $deadline = [DateTime]::UtcNow.AddSeconds($script:CheckTimeoutSec)
        $restored = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 2
            if ((Get-PublicIpv4) -ne '') { $restored = $true; break }
        }
        if (-not $restored) {
            Add-Check 'crash_recovery' 'fail' 'baseline_not_restored'
            return
        }
        $exe = Join-Path $env:ProgramFiles 'beam\beam-client.exe'
        if (-not (Test-Path -LiteralPath $exe)) {
            Add-Check 'crash_recovery' 'fail' 'cleanup_bin_missing'
            return
        }
        $cleanupOk = $false
        try {
            $cp = Start-Process -FilePath $exe -ArgumentList '--cleanup-routes' -NoNewWindow -PassThru
            if ($cp.WaitForExit(15000)) {
                $cleanupOk = ($cp.ExitCode -eq 0)
            } else {
                try { Stop-Process -Id $cp.Id -Force -ErrorAction SilentlyContinue } catch {
                }
                $cleanupOk = $false
            }
        } catch {
            $cleanupOk = $false
        }
        if (-not $cleanupOk) {
            Add-Check 'crash_recovery' 'fail' 'cleanup_failed'
            return
        }
        $leftover = $false
        $splitPrefixes = @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')
        foreach ($family in @('IPv4', 'IPv6')) {
            $routes = Get-NetRoute -AddressFamily $family -ErrorAction SilentlyContinue
            foreach ($r in $routes) {
                if ($splitPrefixes -contains $r.DestinationPrefix) {
                    $leftover = $true
                    break
                }
            }
            if ($leftover) { break }
        }
        if ($leftover) {
            Add-Check 'crash_recovery' 'fail' 'split_route_remains'
            return
        }
        Add-Check 'crash_recovery' 'pass' 'ok'
    } catch {
        Add-Check 'crash_recovery' 'fail' 'check_error'
    }
}

try {
    $link = $env:BEAM_LIVE_VLESS_LINK
    if ([string]::IsNullOrWhiteSpace($link)) {
        throw 'BEAM_LIVE_VLESS_LINK is empty or unset.'
    }
    if ($link -notmatch '^vless://') {
        throw 'BEAM_LIVE_VLESS_LINK does not start with vless://.'
    }
    Write-Host 'secret_present=true'
    # Mask the whole link first so no future error path can echo any of it.
    Write-Host ('::add-mask::' + $link)

    # Mask the VPS host/IP and every parsed secret field before any check runs.
    $hostMatch = [regex]::Match($link, '^vless://(?<user>[^@]+)@(?<host>\[[^\]]+\]|[^:/?#]+)')
    $vpsHost = ''
    if ($hostMatch.Success) {
        $vpsUser = $hostMatch.Groups['user'].Value
        $vpsHost = $hostMatch.Groups['host'].Value.Trim('[', ']')
        if ($vpsUser -ne '') { Write-Host ("::add-mask::" + $vpsUser); $script:RedactList += $vpsUser }
    }
    foreach ($pattern in @('(?<=pbk=)[^&#]+', '(?<=sid=)[^&#]+')) {
        $m = [regex]::Match($link, $pattern)
        if ($m.Success) { Write-Host ("::add-mask::" + $m.Value); $script:RedactList += $m.Value }
    }
    if ($vpsHost -ne '') { Write-Host ("::add-mask::" + $vpsHost); $script:RedactList += $vpsHost }
    $script:RedactList += $link
    $resolvedVps = ''
    if ($vpsHost -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $resolvedVps = $vpsHost
    } elseif ($vpsHost -ne '') {
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($vpsHost)
            foreach ($a in $addrs) {
                if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $resolvedVps = $a.ToString()
                    break
                }
            }
        } catch {
            $resolvedVps = ''
        }
    }
    $script:VpsIpv4 = $resolvedVps
    if ($script:VpsIpv4 -ne '') { Write-Host ("::add-mask::" + $script:VpsIpv4); $script:RedactList += $script:VpsIpv4 }

    $baseline = Get-PublicIpv4
    Write-Host ('baseline_egress_reachable=' + ($baseline -ne '').ToString().ToLowerInvariant())

    $installPs1 = Join-Path $PackageDir 'install.ps1'
    if (-not (Test-Path -LiteralPath $installPs1)) {
        throw "install.ps1 not found under $PackageDir."
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installPs1 -NoAutoStart -NoStart -NonInteractive
    if ($LASTEXITCODE -ne 0) { throw "install_failed exit=$LASTEXITCODE" }

    $running = $false
    for ($i = 0; $i -lt 20; $i++) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (($null -ne $svc) -and ($svc.Status -eq 'Running')) { $running = $true; break }
        Start-Sleep -Seconds 1
    }
    Write-Host ('service_running=' + $running.ToString().ToLowerInvariant())
    if (-not $running) { throw 'service_not_running' }

    $status = Read-Status
    Write-Host ('ipc_status_ok=' + ($null -ne $status['state']).ToString().ToLowerInvariant())

    $importReply = Invoke-Ipc -Line ("IMPORT_LINK " + $link)
    if (-not $importReply.StartsWith('OK ')) { throw 'import_failed' }
    Write-Host 'import_ok=true'

    # Positive control: before CONNECT nothing blocks plaintext DNS, so the same
    # bound probes must reach a public resolver. Only tuples whose control
    # answered can later prove a block.
    try {
        Ensure-BoundDnsType
        $ctlPlan = @(Get-DnsProbePlan -BeamIf (Get-BeamIfIndex))
        if ($ctlPlan.Count -eq 0) {
            Write-Host 'dns_control_probe=no_physical_if'
        }
        $ctlIndex = 0
        foreach ($ctl in $ctlPlan) {
            foreach ($t in @('1.1.1.1', '8.8.8.8')) {
                $ctlIndex = $ctlIndex + 1
                $key = ([string]$ctl['IfIndex']) + '|' + $t
                $ok = $false
                try {
                    $rcCtl = [BeamBoundDns]::TryBoundQuery($t, [int]$ctl['IfIndex'], [string]$ctl['LocalIp'], $DualStackName, 3000)
                    if ($rcCtl -eq 1) { $ok = $true }
                } catch {
                    $ok = $false
                }
                $script:ControlResults[$key] = $ok
                Write-Host ('dns_control_probe_' + [string]$ctlIndex + '=' + $ok.ToString().ToLowerInvariant())
            }
        }
    } catch {
        Write-Host 'dns_control_probe=error'
    }

    $connectReply = Invoke-Ipc -Line 'CONNECT'
    if (-not $connectReply.StartsWith('OK ')) { throw 'connect_rejected' }
    Write-Host 'connect_accepted=true'

    if (-not (Wait-Connected -TimeoutSec $ConnectTimeoutSec)) {
        foreach ($n in @('route_fail_closed', 'dns_leak', 'ipv6_egress', 'service_restart', 'crash_recovery')) {
            Add-Check $n 'skip' 'not_connected'
        }
        throw 'never_connected'
    }
    Write-Host 'connected=true'
    if (-not (Test-BeamAdapterUp)) { throw 'wintun_not_up' }
    Write-Host 'wintun_adapter_up=true'

    Test-RouteFailClosed
    Test-DnsLeak
    Test-Ipv6Egress
    Test-ServiceRestart
    Test-CrashRecovery
} catch {
    $fatalError = $_.Exception.Message
    # Exception text is ours or the sanitized server reply; never secret-bearing.
    Write-Host ("live_checks_error=" + $fatalError)
} finally {
    # Preserve a SCRUBBED copy of the service log before uninstall deletes
    # %ProgramData%\beam, so a failure artifact cannot carry a secret.
    try {
        $logDir = Join-Path $env:RUNNER_TEMP 'beam-logs'
        $null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue
        $dataDir = Join-Path $env:ProgramData 'beam'
        if (Test-Path -LiteralPath $dataDir) {
            foreach ($src in @(Get-ChildItem -LiteralPath $dataDir -Filter '*.log' -ErrorAction SilentlyContinue)) {
                $body = ''
                try { $body = Get-Content -LiteralPath $src.FullName -Raw -ErrorAction Stop } catch { $body = '' }
                foreach ($secret in $script:RedactList) {
                    if ([string]::IsNullOrEmpty($secret)) { continue }
                    $body = $body.Replace($secret, '<secret>')
                }
                $body = [regex]::Replace($body, '\d{1,3}(\.\d{1,3}){3}', '<ip>')
                $body = [regex]::Replace($body, '([0-9a-fA-F]{2}:){4,}[0-9a-fA-F:]+', '<v6>')
                $dest = Join-Path $logDir $src.Name
                Set-Content -LiteralPath $dest -Value $body -Encoding UTF8 -ErrorAction Stop
            }
        }
        Write-Host 'logs_preserved=true'
    } catch {
        Write-Host 'logs_preserved=false'
    }
    # Print the WFP/route/dns lines from the service log so a failing run shows
    # why the leak guard did or did not block. IP literals are redacted.
    try {
        $logPath = Join-Path $env:ProgramData 'beam\beam-client.log'
        if (Test-Path -LiteralPath $logPath) {
            $hits = @(Select-String -LiteralPath $logPath -Pattern 'leak guard|block_physical_dns|split routes|wfp|dns interceptor' -ErrorAction SilentlyContinue | Select-Object -Last 15)
            $digestIndex = 0
            foreach ($h in $hits) {
                $text = [string]$h.Line
                foreach ($secret in $script:RedactList) {
                    if ([string]::IsNullOrEmpty($secret)) { continue }
                    $text = $text.Replace($secret, '<secret>')
                }
                $text = [regex]::Replace($text, '\d{1,3}(\.\d{1,3}){3}', '<ip>')
                $text = [regex]::Replace($text, '([0-9a-fA-F]{2}:){4,}[0-9a-fA-F:]+', '<v6>')
                if ($text.Length -gt 220) { $text = $text.Substring(0, 220) }
                $digestIndex = $digestIndex + 1
                Write-Host ('log_digest=' + $digestIndex + ': ' + $text)
            }
            Write-Host ('log_digest_lines=' + $digestIndex)
        } else {
            Write-Host 'log_digest=missing'
        }
    } catch {
        Write-Host 'log_digest=error'
    }
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
    Write-Host ('service_deleted=' + $svcGone.ToString().ToLowerInvariant())
    $restored = $false
    $restoreDeadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $restoreDeadline) {
        if ((Get-PublicIpv4) -ne '') { $restored = $true; break }
        Start-Sleep -Seconds 2
    }
    Write-Host ('baseline_internet_restored=' + $restored.ToString().ToLowerInvariant())
    if (-not $restored) {
        # A bricked host must never exit 0, even when the workflow wrapper is absent.
        $fatalError = 'baseline_not_restored'
    }

    if (($script:checksFailed -gt 0) -or ($fatalError -ne '')) {
        $overall = 'FAIL'
    } elseif ($script:checksPassed -eq 0) {
        # Skips alone are not evidence: never report a green run with no pass.
        $overall = 'FAIL'
    } else {
        $overall = 'PASS'
    }
    $lines = @("windows-live-checks: $overall (passed=" + [string]$script:checksPassed + " failed=" + [string]$script:checksFailed + ")") + @($checkLines)
    $summary = ($lines -join "`n")
    Write-Host $summary
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
    }
    if ($overall -eq 'FAIL') { $exitCode = 1 }
}

exit $exitCode
