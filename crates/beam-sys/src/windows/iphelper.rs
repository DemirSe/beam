//! Windows IP Helper API wrappers (addresses, MTU, DNS, routes, change watchers).
//!
//! Every helper here calls the Windows IP Helper API directly, so a routing or
//! DNS change never shells out to `route.exe` or `netsh.exe`. Winsock-shaped
//! values are passed to the API as `SOCKADDR_INET` rows, and every failure
//! becomes an [`io::Error`] that keeps the Win32 error code.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS,
    FreeLibrary, HANDLE, HMODULE, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2, FreeMibTable,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, GetIpForwardTable2,
    GetIpInterfaceEntry, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2, SetInterfaceDnsSettings,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET, SOCKET_ADDRESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

/// Lifetime value the IP Helper API treats as "never expires".
const INFINITE_LIFETIME: u32 = u32::MAX;

/// Port a DNS server address is reported on.
const DNS_PORT: u16 = 53;

/// `GetAdaptersAddresses` retries before the size negotiation is reported.
const MAX_ADAPTER_LOOKUP_ATTEMPTS: usize = 4;

/// First `GetAdaptersAddresses` buffer size, in bytes.
const INITIAL_ADAPTERS_BUFFER_BYTES: u32 = 16 * 1024;

/// Upper bound for the `GetAdaptersAddresses` buffer, in bytes.
const MAX_ADAPTERS_BUFFER_BYTES: u32 = 1024 * 1024;

/// Adapter entries scanned per lookup, so a malformed list cannot loop forever.
const MAX_ADAPTERS_SCANNED: usize = 1024;

/// DNS server entries scanned per adapter, for the same reason.
const MAX_DNS_SERVERS_SCANNED: usize = 64;

/// A route row as the tunnel manages it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceRoute {
    /// Prefix the route matches.
    pub destination: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Next hop, or the on-link address when the prefix is directly reachable.
    pub next_hop: IpAddr,
    /// LUID of the interface the route uses.
    pub interface_luid: u64,
    /// Index of the interface the route uses.
    pub interface_index: u32,
    /// Route metric offset added to the interface metric.
    pub metric: u32,
}

/// A default gateway that carries real traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalGateway {
    /// LUID of the interface the default route uses.
    pub interface_luid: u64,
    /// Index of the interface the default route uses.
    pub interface_index: u32,
    /// Next hop of the default route.
    pub next_hop: IpAddr,
    /// Route metric offset of the default route.
    pub metric: u32,
}

/// Best default gateway found per address family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhysicalGateways {
    /// IPv4 default gateway.
    pub v4: Option<PhysicalGateway>,
    /// IPv6 default gateway.
    pub v6: Option<PhysicalGateway>,
}

/// Converts interface `luid` into the interface index Windows reports.
pub fn luid_to_index(luid: u64) -> io::Result<u32> {
    let luid = net_luid(luid);
    let mut index = 0_u32;
    // SAFETY: both pointers borrow live locals of the exact types
    // `ConvertInterfaceLuidToIndex` expects, and the call keeps neither.
    let code = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    if code != ERROR_SUCCESS {
        return Err(win32_error(code));
    }
    Ok(index)
}

/// Converts interface `luid` into the stable interface GUID Windows reports.
pub fn luid_to_guid(luid: u64) -> io::Result<windows_sys::core::GUID> {
    let luid = net_luid(luid);
    let mut guid = windows_sys::core::GUID::default();
    // SAFETY: `luid` is a live `NET_LUID_LH` and `guid` is a live, writable
    // `GUID`; the call writes only into `guid` and keeps neither pointer.
    let code = unsafe { ConvertInterfaceLuidToGuid(&raw const luid, &raw mut guid) };
    if code != ERROR_SUCCESS {
        return Err(win32_error(code));
    }
    Ok(guid)
}

/// Adds `ip` with `prefix_len` to the unicast address table of interface `luid`.
///
/// An address that already exists on the interface counts as success, which
/// keeps a repeated connect idempotent.
pub fn set_interface_unicast_ip(luid: u64, ip: IpAddr, prefix_len: u8) -> io::Result<()> {
    check_prefix_len(ip, prefix_len)?;

    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a live, writable `MIB_UNICASTIPADDRESS_ROW` of exactly
    // the type the call expects; it writes only into `row`.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.Address = ip_to_sockaddr(ip);
    row.InterfaceLuid = net_luid(luid);
    // Both origins must be manual or both unchanged, otherwise the API rejects
    // the row as an invalid parameter.
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.OnLinkPrefixLength = prefix_len;
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    // Windows 10 and later accept `IpDadStatePreferred` and skip the tentative
    // period, so the address is usable as soon as the tunnel comes up.
    row.DadState = IpDadStatePreferred;
    row.SkipAsSource = false;

    // SAFETY: `row` is a fully initialized unicast address row that stays alive
    // and is not mutated for the duration of the call.
    let code = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if code == ERROR_SUCCESS || code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    Err(win32_error(code))
}

/// Sets the network layer MTU and the manual interface metric of `luid`.
///
/// `family_v6` selects the IPv6 row of the interface; IPv4 and IPv6 keep
/// separate metrics. The metric applies only because automatic metric
/// selection is turned off in the same call.
pub fn set_interface_mtu_and_metric(
    luid: u64,
    family_v6: bool,
    mtu: u32,
    metric: u32,
) -> io::Result<()> {
    if mtu == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface MTU must be positive",
        ));
    }

    let family = if family_v6 { AF_INET6 } else { AF_INET };
    let mut row = interface_row(luid, family)?;
    row.NlMtu = mtu;
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // The IP Helper API rejects a non-zero site prefix length on an IPv4 row.
    row.SitePrefixLength = 0;

    // SAFETY: `row` was filled by `GetIpInterfaceEntry` for this interface and
    // family and stays alive for the call, which writes nothing back to it.
    let code = unsafe { SetIpInterfaceEntry(&raw mut row) };
    if code == ERROR_SUCCESS {
        return Ok(());
    }
    Err(win32_error(code))
}

/// Replaces the DNS servers of interface `luid`.
///
/// An empty `servers` slice clears the static servers, which puts the adapter
/// back on the DNS servers its DHCP or router advertisement supplied.
pub fn set_interface_dns(luid: u64, servers: &[IpAddr]) -> io::Result<()> {
    let interface = luid_to_guid(luid)?;

    let mut nameserver: Vec<u16> = format_dns_nameserver_list(servers).encode_utf16().collect();
    // Always NUL-terminate, including the empty list: Windows clears the static
    // servers back to DHCP for `L""` but not reliably for a null pointer.
    nameserver.push(0);

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: nameserver.as_mut_ptr(),
        ..DNS_INTERFACE_SETTINGS::default()
    };

    // SAFETY: `settings` is a live version 1 `DNS_INTERFACE_SETTINGS`, and its
    // `NameServer` pointer references the NUL-terminated buffer above, which
    // outlives the call. The API keeps neither pointer.
    let code = unsafe { SetInterfaceDnsSettings(interface, &raw const settings) };
    if code == ERROR_SUCCESS {
        return Ok(());
    }
    Err(win32_error(code))
}

/// Empties the Windows DNS resolver cache.
///
/// `dnsapi.dll` is loaded from the system directory, so a planted DLL next to
/// the executable cannot answer for it.
pub fn flush_dns_cache() -> io::Result<()> {
    DnsApiLibrary::load()?.flush_resolver_cache()
}

/// Adds `route` to the forward table.
///
/// A route that already exists counts as success, which keeps a repeated
/// connect idempotent.
pub fn add_route(route: &InterfaceRoute) -> io::Result<()> {
    let row = forward_row(route)?;
    // SAFETY: `row` is a fully initialized forward row that stays alive and is
    // not mutated for the duration of the call.
    let code = unsafe { CreateIpForwardEntry2(&raw const row) };
    if code == ERROR_SUCCESS || code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    Err(win32_error(code))
}

/// Removes `route` from the forward table.
///
/// A route that is already gone counts as success.
pub fn delete_route(route: &InterfaceRoute) -> io::Result<()> {
    let row = forward_row(route)?;
    // SAFETY: `row` is a fully initialized forward row that stays alive and is
    // not mutated for the duration of the call.
    let code = unsafe { DeleteIpForwardEntry2(&raw const row) };
    if code == ERROR_SUCCESS || code == ERROR_NOT_FOUND {
        return Ok(());
    }
    Err(win32_error(code))
}

/// Reports whether `destination` is already routed through `interface_luid`.
pub fn route_exists(destination: IpAddr, prefix_len: u8, interface_luid: u64) -> io::Result<bool> {
    check_prefix_len(destination, prefix_len)?;

    let table = ForwardTable::load()?;
    for row in table.rows() {
        if row.DestinationPrefix.PrefixLength != prefix_len {
            continue;
        }
        let family = sockaddr_inet_family(&row.DestinationPrefix.Prefix);
        if sockaddr_inet_to_ip(family, &row.DestinationPrefix.Prefix) != Some(destination) {
            continue;
        }
        if luid_value(&row.InterfaceLuid) == interface_luid {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Finds the default gateway with the lowest effective metric per family.
///
/// The scan skips routes that belong to `exclude_luid` (the tunnel adapter),
/// loopback routes, interfaces that are not connected, and interfaces that
/// disable default routes. The effective metric is the route metric plus the
/// interface metric, which is the ranking Windows uses for default routes.
pub fn detect_physical_gateways(exclude_luid: u64) -> io::Result<PhysicalGateways> {
    let table = ForwardTable::load()?;
    let mut v4: Option<(PhysicalGateway, u32)> = None;
    let mut v6: Option<(PhysicalGateway, u32)> = None;

    for row in table.rows() {
        if row.DestinationPrefix.PrefixLength != 0 || row.Loopback {
            continue;
        }
        let luid = luid_value(&row.InterfaceLuid);
        if luid == exclude_luid || luid_if_type(luid) == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let family = sockaddr_inet_family(&row.DestinationPrefix.Prefix);
        if family != AF_INET && family != AF_INET6 {
            continue;
        }
        let Some(next_hop) = sockaddr_inet_to_ip(family, &row.NextHop) else {
            continue;
        };
        if !is_usable_gateway(next_hop) {
            continue;
        }
        // An interface that is gone or down has no usable gateway; the lookup
        // failing means the same thing, so both skip the row.
        let Ok(state) = interface_row(luid, family) else {
            continue;
        };
        if !state.Connected || state.DisableDefaultRoutes {
            continue;
        }

        let gateway = PhysicalGateway {
            interface_luid: luid,
            interface_index: row.InterfaceIndex,
            next_hop,
            metric: row.Metric,
        };
        if family == AF_INET {
            v4 = select_best_gateway(v4, gateway, state.Metric);
        } else {
            v6 = select_best_gateway(v6, gateway, state.Metric);
        }
    }

    Ok(PhysicalGateways {
        v4: v4.map(|(gateway, _)| gateway),
        v6: v6.map(|(gateway, _)| gateway),
    })
}

/// Returns the first usable DNS server of the physical adapters.
///
/// Adapters on `exclude_luid` (the tunnel adapter), loopback adapters, and
/// adapters that are not up are skipped, and so are servers that cannot answer
/// a query: loopback, unspecified, link-local, multicast, the Windows
/// site-local sentinels, and any address inside `exclude_v4_net`.
pub fn detect_system_local_dns(
    exclude_luid: u64,
    exclude_v4_net: Option<(Ipv4Addr, u8)>,
) -> io::Result<Option<SocketAddr>> {
    let adapters = AdapterBuffer::load()?;
    let mut adapter = adapters.first();
    let mut scanned_adapters = 0_usize;

    while !adapter.is_null() && scanned_adapters < MAX_ADAPTERS_SCANNED {
        scanned_adapters += 1;
        // SAFETY: `adapter` points at one initialized `IP_ADAPTER_ADDRESSES_LH`
        // entry of the live `adapters` buffer, and `Next` is read before the
        // buffer is dropped.
        let entry = unsafe { &*adapter };
        adapter = entry.Next;

        if luid_value(&entry.Luid) == exclude_luid
            || entry.OperStatus != IfOperStatusUp
            || entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK
        {
            continue;
        }

        let mut server = entry.FirstDnsServerAddress;
        let mut scanned_servers = 0_usize;
        while !server.is_null() && scanned_servers < MAX_DNS_SERVERS_SCANNED {
            scanned_servers += 1;
            // SAFETY: `server` points at one initialized
            // `IP_ADAPTER_DNS_SERVER_ADDRESS_XP` entry of the live buffer.
            let server_entry = unsafe { &*server };
            server = server_entry.Next;

            let Some(ip) = socket_address_to_ip(&server_entry.Address) else {
                continue;
            };
            if is_usable_dns_server(ip, exclude_v4_net) {
                return Ok(Some(SocketAddr::new(ip, DNS_PORT)));
            }
        }
    }

    Ok(None)
}

/// Event-driven watcher for route and interface changes.
///
/// Both notifications are registered for `AF_UNSPEC` with no initial
/// notification, so the callback runs only when the table actually changes.
/// Dropping the watcher cancels both registrations and then releases the
/// callback; if either cancellation fails, it leaks the callback state instead
/// of risking a use-after-free from a notification thread it could not stop.
pub struct NetworkChangeWatcher {
    context: *mut ChangeContext,
    route: HANDLE,
    interface: HANDLE,
}

impl NetworkChangeWatcher {
    /// Registers the route and interface notifications that call `callback`.
    pub fn start(callback: Arc<dyn Fn() + Send + Sync>) -> io::Result<Self> {
        let context = Box::into_raw(Box::new(ChangeContext {
            callback,
            active: AtomicBool::new(true),
        }));
        let mut watcher = Self {
            context,
            route: ptr::null_mut(),
            interface: ptr::null_mut(),
        };
        watcher.register()?;
        Ok(watcher)
    }

    /// Registers both notifications, keeping each handle as it arrives.
    fn register(&mut self) -> io::Result<()> {
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: `self.context` is a live boxed context that is freed only
        // after both registrations are cancelled in `drop`, and `handle` is a
        // writable local the call fills in.
        let code = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_change_notification),
                self.context.cast(),
                false,
                &raw mut handle,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(win32_error(code));
        }
        self.route = handle;

        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: same as above; the context outlives both registrations.
        let code = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_change_notification),
                self.context.cast(),
                false,
                &raw mut handle,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(win32_error(code));
        }
        self.interface = handle;
        Ok(())
    }
}

impl Drop for NetworkChangeWatcher {
    fn drop(&mut self) {
        if !self.context.is_null() {
            // SAFETY: `self.context` came from `Box::into_raw` and is freed
            // exactly once, further below in this function. Clearing `active`
            // first makes a notification that starts during teardown skip the
            // caller's callback instead of running it.
            unsafe { &*self.context }
                .active
                .store(false, Ordering::Release);
        }
        // Cancel before the free below. Per the MS documentation,
        // `CancelMibChangeNotify2` does not return until every notification
        // callback that is already running has finished (which is why calling
        // it from inside a callback deadlocks), so a successful cancellation
        // synchronises with the callback threads.
        let mut cancelled = true;
        for handle in [self.route, self.interface] {
            if handle.is_null() {
                continue;
            }
            // SAFETY: `handle` came from a successful notification registration
            // that has not been cancelled yet.
            if unsafe { CancelMibChangeNotify2(handle) } != NO_ERROR {
                cancelled = false;
            }
        }
        if self.context.is_null() || !cancelled {
            // A failed cancellation proves nothing about notifications still in
            // flight, so the context is leaked on purpose: one small, bounded
            // leak is better than freeing memory a notification thread may
            // still read.
            return;
        }
        // SAFETY: `self.context` came from `Box::into_raw` and is freed exactly
        // once, here, after both registrations are cancelled and all in-flight
        // callbacks have returned.
        drop(unsafe { Box::from_raw(self.context) });
    }
}

// SAFETY: the watcher owns the only strong reference to the boxed context and
// frees it after both registrations are cancelled with `NO_ERROR`. The raw
// pointer is handed to the IP Helper API and never dereferenced through the
// watcher, so moving the watcher to another thread keeps the same single owner.
unsafe impl Send for NetworkChangeWatcher {}

/// State the IP Helper notification threads share with the caller.
struct ChangeContext {
    callback: Arc<dyn Fn() + Send + Sync>,
    /// False once [`NetworkChangeWatcher::drop`] starts cancelling.
    active: AtomicBool,
}

/// Routes a `NotifyRouteChange2` notification into the shared callback.
///
/// # Safety
/// `context` must be the value passed to `NotifyRouteChange2` and must stay
/// valid until `CancelMibChangeNotify2` returns for that registration.
unsafe extern "system" fn route_change_notification(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: the caller guarantees `context` stays valid for the call.
    unsafe { dispatch_change(context) };
}

/// Routes a `NotifyIpInterfaceChange` notification into the shared callback.
///
/// # Safety
/// `context` must be the value passed to `NotifyIpInterfaceChange` and must
/// stay valid until `CancelMibChangeNotify2` returns for that registration.
unsafe extern "system" fn interface_change_notification(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: the caller guarantees `context` stays valid for the call.
    unsafe { dispatch_change(context) };
}

/// Runs the user callback for one notification.
///
/// # Safety
/// `context` must be null or point at a live [`ChangeContext`].
unsafe fn dispatch_change(context: *const c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller guarantees a live `ChangeContext`, which is freed only
    // after both registrations are cancelled.
    let context = unsafe { &*context.cast::<ChangeContext>() };
    // Drop clears `active` (release) before it cancels the registrations, so a
    // notification that starts during teardown sees the cleared flag (acquire)
    // and returns without calling into the caller.
    if !context.active.load(Ordering::Acquire) {
        return;
    }
    // A panicking callback must not unwind into the IP Helper thread pool, so
    // the panic stops here instead of crossing the FFI boundary.
    let _ = catch_unwind(AssertUnwindSafe(|| (context.callback)()));
}

/// Converts a Win32 error code into an [`io::Error`].
fn win32_error(code: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Rejects a prefix length that does not fit the address family of `ip`.
fn check_prefix_len(ip: IpAddr, prefix_len: u8) -> io::Result<()> {
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("prefix length {prefix_len} exceeds {max} for {ip}"),
        ));
    }
    Ok(())
}

/// Wraps a raw LUID value in the union the IP Helper API expects.
fn net_luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

/// Returns the raw 64-bit value of an initialized `NET_LUID_LH`.
fn luid_value(luid: &NET_LUID_LH) -> u64 {
    // SAFETY: `NET_LUID_LH` is a `u64`-sized union whose `Value` member accepts
    // any bit pattern, and `luid` is a live reference.
    unsafe { luid.Value }
}

/// Returns the interface type stored in the top 16 bits of a LUID.
fn luid_if_type(luid: u64) -> u32 {
    ((luid >> 48) & 0xffff) as u32
}

/// Builds the `SOCKADDR_INET` the IP Helper API expects for `ip`.
fn ip_to_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => address.Ipv4 = sockaddr_v4(v4),
        IpAddr::V6(v6) => address.Ipv6 = sockaddr_v6(v6),
    }
    address
}

/// Builds an IPv4 `SOCKADDR_IN` with an unused port.
fn sockaddr_v4(ip: Ipv4Addr) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET,
        // The address octets are stored in network order, so writing the octet
        // array in native order keeps the exact bytes the stack expects.
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        },
        ..SOCKADDR_IN::default()
    }
}

/// Builds an IPv6 `SOCKADDR_IN6` with an unused port and an empty scope.
fn sockaddr_v6(ip: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: ip.octets() },
        },
        ..SOCKADDR_IN6::default()
    }
}

/// Reads the address family tag of a `SOCKADDR_INET`.
fn sockaddr_inet_family(address: &SOCKADDR_INET) -> ADDRESS_FAMILY {
    // SAFETY: every member of `SOCKADDR_INET` starts with the 16-bit address
    // family, so reading `si_family` is valid for any initialized value of the
    // union while the reference is live.
    unsafe { address.si_family }
}

/// Converts an initialized `SOCKADDR_INET` of the given family into an address.
///
/// A family that does not match the address returns `None` instead of reading
/// the wrong union member.
fn sockaddr_inet_to_ip(family: ADDRESS_FAMILY, address: &SOCKADDR_INET) -> Option<IpAddr> {
    match family {
        AF_INET => {
            // SAFETY: `family` is `AF_INET`, so `Ipv4` is the active member and
            // its address bytes are initialized. `S_addr` holds the four
            // address octets in memory order, which `to_ne_bytes` preserves.
            let bytes = unsafe { address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 => {
            // SAFETY: `family` is `AF_INET6`, so `Ipv6` is the active member and
            // its 16 address bytes are initialized.
            let bytes = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Converts a socket address from the adapter list into an address.
///
/// The reported length decides which socket address layout may be read, so a
/// short buffer is refused instead of over-read.
fn socket_address_to_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    let length = usize::try_from(address.iSockaddrLength).ok()?;
    // SAFETY: the pointer is non-null and addresses an initialized `SOCKADDR`
    // header inside the adapter buffer that is alive for this call.
    let family = unsafe { (*address.lpSockaddr).sa_family };
    match family {
        AF_INET if length >= size_of::<SOCKADDR_IN>() => {
            // SAFETY: the family tag is `AF_INET` and the reported length covers
            // a whole `SOCKADDR_IN`, so the pointer addresses an initialized
            // value of that type.
            let ipv4 = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
            // SAFETY: `S_addr` is the initialized address member of the union.
            let bytes = unsafe { ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 if length >= size_of::<SOCKADDR_IN6>() => {
            // SAFETY: the family tag is `AF_INET6` and the reported length covers
            // a whole `SOCKADDR_IN6`, so the pointer addresses an initialized
            // value of that type with all 16 address bytes set.
            let ipv6 = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe { ipv6.sin6_addr.u.Byte })))
        }
        _ => None,
    }
}

/// Reports whether `ip` can be the next hop of a default route.
///
/// Unspecified, loopback, multicast, IPv4 broadcast, and IPv4 link-local
/// addresses are excluded. An IPv6 link-local next hop stays, because a router
/// advertises its link-local address and the interface LUID scopes it.
fn is_usable_gateway(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast()),
    }
}

/// Reports whether `ip` can answer DNS queries for the tunnel.
///
/// Link-local servers are excluded because the answer does not say which link
/// they belong to.
fn is_usable_dns_server(ip: IpAddr, exclude_v4_net: Option<(Ipv4Addr, u8)>) -> bool {
    if !is_usable_gateway(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_link_local() && !exclude_v4_net.is_some_and(|net| cidr_contains_v4(net, v4))
        }
        IpAddr::V6(v6) => !is_link_local_v6(v6) && !is_windows_site_local_dns(v6),
    }
}

/// Reports whether `ip` is in the IPv6 link-local range `fe80::/10`.
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Reports whether `ip` is one of the Windows site-local DNS sentinels.
///
/// `fec0:0:0:ffff::1` to `fec0:0:0:ffff::3` are placeholders the stack reports
/// when a scope has no real IPv6 server, so they must not be handed to a client.
fn is_windows_site_local_dns(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0xfec0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0xffff
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && matches!(segments[7], 1..=3)
}

/// Reports whether `candidate` is inside the IPv4 network `net`.
fn cidr_contains_v4(net: (Ipv4Addr, u8), candidate: Ipv4Addr) -> bool {
    let (base, prefix_len) = net;
    if prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    (u32::from(base) & mask) == (u32::from(candidate) & mask)
}

/// Renders `servers` as the space-separated list the DNS API expects.
fn format_dns_nameserver_list(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Keeps the gateway with the lower effective metric.
///
/// The effective metric is the route metric plus the interface metric, which is
/// the weight Windows uses to rank default routes. A tie keeps the earlier
/// candidate, so the scan stays deterministic.
fn select_best_gateway(
    best: Option<(PhysicalGateway, u32)>,
    candidate: PhysicalGateway,
    interface_metric: u32,
) -> Option<(PhysicalGateway, u32)> {
    let effective = candidate.metric.saturating_add(interface_metric);
    match best {
        Some((gateway, best_effective)) if best_effective <= effective => {
            Some((gateway, best_effective))
        }
        _ => Some((candidate, effective)),
    }
}

/// Reads the interface row of `luid` for `family`.
fn interface_row(luid: u64, family: ADDRESS_FAMILY) -> io::Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` is a live, writable `MIB_IPINTERFACE_ROW` of exactly the
    // type the call expects, and the call writes only into it.
    unsafe { InitializeIpInterfaceEntry(&raw mut row) };
    row.Family = family;
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: the row names one interface and family, so the call reads that
    // interface and writes the result into the same live row.
    let code = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if code != ERROR_SUCCESS {
        return Err(win32_error(code));
    }
    Ok(row)
}

/// Builds the forward row that `add_route` and `delete_route` pass to the API.
fn forward_row(route: &InterfaceRoute) -> io::Result<MIB_IPFORWARD_ROW2> {
    check_prefix_len(route.destination, route.prefix_len)?;
    if route.destination.is_ipv4() != route.next_hop.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route next hop must use the address family of the destination",
        ));
    }

    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a live, writable `MIB_IPFORWARD_ROW2` of exactly the type
    // the call expects, and the call writes only into it.
    unsafe { InitializeIpForwardEntry(&raw mut row) };
    row.InterfaceLuid = net_luid(route.interface_luid);
    row.InterfaceIndex = route.interface_index;
    row.DestinationPrefix.Prefix = ip_to_sockaddr(route.destination);
    row.DestinationPrefix.PrefixLength = route.prefix_len;
    row.NextHop = ip_to_sockaddr(route.next_hop);
    row.Metric = route.metric;
    // The IP Helper API rejects a non-zero site prefix length on an IPv4 route.
    row.SitePrefixLength = 0;
    Ok(row)
}

/// Owns a `MIB_IPFORWARD_TABLE2` and frees it when dropped.
struct ForwardTable {
    table: *mut MIB_IPFORWARD_TABLE2,
}

impl ForwardTable {
    /// Reads the whole forward table for both address families.
    fn load() -> io::Result<Self> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        // SAFETY: `table` is a writable local the call fills with an
        // `iphlpapi.dll`-owned table, and `AF_UNSPEC` asks for both families.
        let code = unsafe { GetIpForwardTable2(AF_UNSPEC, &raw mut table) };
        if code != ERROR_SUCCESS {
            return Err(win32_error(code));
        }
        if table.is_null() {
            return Err(io::Error::other("GetIpForwardTable2 returned a null table"));
        }
        Ok(Self { table })
    }

    /// Borrows every row of the table.
    fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
        // SAFETY: `self.table` is a non-null table returned by
        // `GetIpForwardTable2`, which allocates `NumEntries` rows in the
        // trailing `Table` array. The slice borrows from `self`, so it cannot
        // outlive the allocation freed in `drop`.
        unsafe {
            let count = (*self.table).NumEntries as usize;
            let rows = ptr::addr_of!((*self.table).Table).cast::<MIB_IPFORWARD_ROW2>();
            std::slice::from_raw_parts(rows, count)
        }
    }
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        // SAFETY: `self.table` came from `GetIpForwardTable2` and is freed
        // exactly once here while no borrow of it is alive.
        unsafe { FreeMibTable(self.table.cast()) };
    }
}

/// Owns the `GetAdaptersAddresses` result buffer for one lookup.
struct AdapterBuffer {
    storage: Vec<u64>,
}

impl AdapterBuffer {
    /// Fills the adapter list, growing the buffer at most a few times.
    fn load() -> io::Result<Self> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;
        let mut size = INITIAL_ADAPTERS_BUFFER_BYTES;
        let mut storage: Vec<u64> = Vec::new();

        for _ in 0..MAX_ADAPTER_LOOKUP_ATTEMPTS {
            size = size.clamp(INITIAL_ADAPTERS_BUFFER_BYTES, MAX_ADAPTERS_BUFFER_BYTES);
            // `u64` elements keep the buffer 8-byte aligned for the adapter
            // structs, and the element count covers at least `size` bytes.
            storage.clear();
            storage.resize(size.div_ceil(8) as usize, 0);

            // SAFETY: `storage` holds at least `size` bytes behind an aligned
            // pointer, which is what `size` reports to the API. The call fills
            // that memory with one `IP_ADAPTER_ADDRESSES_LH` list and frees the
            // temporary storage itself, so only the returned buffer is read.
            let code = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    ptr::null(),
                    storage.as_mut_ptr().cast(),
                    &raw mut size,
                )
            };
            if code == ERROR_SUCCESS {
                return Ok(Self { storage });
            }
            if code != ERROR_BUFFER_OVERFLOW {
                return Err(win32_error(code));
            }
            // The call rewrote `size` with the length it needs, and the next
            // attempt allocates that.
        }

        Err(io::Error::other(format!(
            "GetAdaptersAddresses did not fit in {MAX_ADAPTERS_BUFFER_BYTES} bytes after {MAX_ADAPTER_LOOKUP_ATTEMPTS} attempts"
        )))
    }

    /// Returns the first adapter of the list, or null for an empty list.
    fn first(&self) -> *const IP_ADAPTER_ADDRESSES_LH {
        self.storage.as_ptr().cast()
    }
}

/// Handle to the system `dnsapi.dll`, released when dropped.
struct DnsApiLibrary(HMODULE);

impl DnsApiLibrary {
    /// Loads `dnsapi.dll` from the system directory.
    fn load() -> io::Result<Self> {
        let name: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
        // call, the file handle is optional and passed as null, and the flags
        // keep the search inside the system directory.
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(module))
    }

    /// Empties the resolver cache through `DnsFlushResolverCache`.
    fn flush_resolver_cache(&self) -> io::Result<()> {
        // SAFETY: the module handle is live, and the name is a NUL-terminated
        // ASCII export name the call only reads.
        let Some(entry) =
            (unsafe { GetProcAddress(self.0, c"DnsFlushResolverCache".as_ptr().cast()) })
        else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "dnsapi.dll exports no DnsFlushResolverCache",
            ));
        };
        // SAFETY: the pointer is the documented `DnsFlushResolverCache` export of
        // the system `dnsapi.dll`, which takes no arguments and returns a BOOL.
        let flush: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(entry) };
        // SAFETY: the signature above matches the export, the module stays
        // loaded for the call, and the function dereferences no caller memory.
        if unsafe { flush() } == 0 {
            return Err(io::Error::other("DnsFlushResolverCache returned FALSE"));
        }
        Ok(())
    }
}

impl Drop for DnsApiLibrary {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `LoadLibraryExW` and is
        // released exactly once here, after every call into it returned.
        unsafe { FreeLibrary(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PhysicalGateway, cidr_contains_v4, format_dns_nameserver_list, ip_to_sockaddr,
        is_windows_site_local_dns, select_best_gateway, sockaddr_inet_family, sockaddr_inet_to_ip,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn gateway(luid: u64, next_hop: &str, metric: u32) -> PhysicalGateway {
        PhysicalGateway {
            interface_luid: luid,
            interface_index: luid as u32,
            next_hop: next_hop.parse().expect("test gateway address"),
            metric,
        }
    }

    #[test]
    fn windows_site_local_dns_matches_only_the_sentinels() {
        for suffix in 1..=3 {
            let address = format!("fec0:0:0:ffff::{suffix}")
                .parse::<Ipv6Addr>()
                .expect("sentinel address");
            assert!(
                is_windows_site_local_dns(address),
                "{address} is a sentinel"
            );
        }
        for other in [
            "fec0:0:0:ffff::4",
            "fec0:0:0:ffff:0:0:0:0",
            "fec0:0:0:fffe::1",
            "fe80::1",
            "2606:4700::1111",
            "::",
        ] {
            let address = other.parse::<Ipv6Addr>().expect("test address");
            assert!(!is_windows_site_local_dns(address), "{address} is not");
        }
    }

    #[test]
    fn select_best_gateway_prefers_the_lower_effective_metric() {
        // Route metric 10 on an interface with metric 5 beats route metric 20
        // on an interface with metric 1: 15 against 21.
        let chosen = select_best_gateway(None, gateway(1, "192.168.1.1", 10), 5);
        let chosen = select_best_gateway(chosen, gateway(2, "192.168.2.1", 20), 1);
        let (best, effective) = chosen.expect("a gateway is selected");
        assert_eq!(best.interface_luid, 1);
        assert_eq!(effective, 15);
    }

    #[test]
    fn select_best_gateway_keeps_the_first_on_a_tie() {
        let first = gateway(1, "192.168.1.1", 10);
        let second = gateway(2, "192.168.2.1", 10);
        let chosen = select_best_gateway(Some((first.clone(), 10)), second, 0);
        assert_eq!(chosen.expect("a gateway is selected").0, first);
    }

    #[test]
    fn select_best_gateway_saturates_the_metric_sum() {
        let chosen = select_best_gateway(None, gateway(1, "192.168.1.1", u32::MAX), 1);
        assert_eq!(chosen.expect("a gateway is selected").1, u32::MAX);
    }

    #[test]
    fn format_dns_nameserver_list_separates_servers_with_spaces() {
        let servers = [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6("2606:4700::1111".parse().expect("test address")),
        ];
        assert_eq!(
            format_dns_nameserver_list(&servers),
            "1.1.1.1 2606:4700::1111"
        );
        assert_eq!(format_dns_nameserver_list(&[]), "");
    }

    #[test]
    fn cidr_contains_v4_masks_the_prefix() {
        let net = (Ipv4Addr::new(10, 0, 0, 0), 8);
        assert!(cidr_contains_v4(net, Ipv4Addr::new(10, 255, 255, 254)));
        assert!(!cidr_contains_v4(net, Ipv4Addr::new(11, 0, 0, 1)));

        let host = (Ipv4Addr::new(192, 168, 1, 5), 32);
        assert!(cidr_contains_v4(host, Ipv4Addr::new(192, 168, 1, 5)));
        assert!(!cidr_contains_v4(host, Ipv4Addr::new(192, 168, 1, 6)));

        let all = (Ipv4Addr::UNSPECIFIED, 0);
        assert!(cidr_contains_v4(all, Ipv4Addr::new(8, 8, 8, 8)));

        let invalid = (Ipv4Addr::new(10, 0, 0, 0), 33);
        assert!(!cidr_contains_v4(invalid, Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn sockaddr_roundtrip_preserves_addresses() {
        for text in ["192.0.2.17", "10.1.2.3", "::1", "2606:4700::1111"] {
            let address = text.parse::<IpAddr>().expect("test address");
            let sockaddr = ip_to_sockaddr(address);
            let family = sockaddr_inet_family(&sockaddr);
            assert_eq!(sockaddr_inet_to_ip(family, &sockaddr), Some(address));
        }
    }
}
