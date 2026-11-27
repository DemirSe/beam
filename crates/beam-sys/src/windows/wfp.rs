//! Dynamic Windows Filtering Platform (WFP) DNS-leak and kill-switch guard.
//!
//! The guard opens the WFP engine with `FWPM_SESSION_FLAG_DYNAMIC`, so Windows
//! removes every filter it adds as soon as the process exits, crashes, or is
//! killed. No filter is ever persistent, and the machine cannot be left with a
//! dead kill switch after a hard kill.
//!
//! Filters live in one sublayer with weight `u16::MAX` and are ordered by fixed
//! `FWP_UINT8` weights inside it: WFP evaluates the highest weight first, so a
//! permit at a higher weight wins over a block at a lower weight. The layout is
//! deliberately identity-free:
//!
//! | Weight | Filter |
//! |---|---|
//! | 15 | permit loopback |
//! | 14 | permit this executable (`ALE_APP_ID`) |
//! | 13 | permit the tunnel interface (`tun_luid`) |
//! | 12 | permit DHCP and IPv6 neighbour discovery |
//! | 10 | permit `permit_cidrs` destinations |
//! | 6 | permit this executable to the local DNS resolver (port 53) |
//! | 5 | block outbound DNS (remote port 53) |
//! | 0 | block all other outbound traffic |
//!
//! Only the outbound `ALE_AUTH_CONNECT_V4` and `ALE_AUTH_CONNECT_V6` layers are
//! filtered: the leak this guards against is traffic that leaves through a
//! physical interface, and inbound filters would only break the encrypted
//! transport to the server.
//!
//! WFP rejects a filter that repeats a `fieldKey` with
//! `FWP_E_DUPLICATE_CONDITION`, so destinations and protocols that Or together
//! become one filter each instead of extra conditions in a shared filter.

use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ALL_SET, FWP_MATCH_RANGE, FWP_MATCH_TYPE, FWP_RANGE_TYPE, FWP_RANGE0,
    FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::core::GUID;

/// Key of the Beam WFP sublayer.
///
/// The key is fixed so that a later version can find and replace the filters of
/// an earlier one inside the same dynamic session. It must never be reused by
/// another product.
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x0d3a_5f2b_8f14_4c6f_9b7e_2a1d_3c5e_7f90);

/// Highest weight value a WFP `FWP_UINT8` filter weight may carry.
pub const MAX_FILTER_WEIGHT: u8 = 15;

/// Permit loopback traffic on any interface.
pub const WEIGHT_PERMIT_LOOPBACK: u8 = 15;

/// Permit everything this executable connects to, including the tunnel server.
///
/// This permit outranks [`WEIGHT_BLOCK_DNS`] on purpose: the built-in DNS
/// interceptor must reach the physical LAN DNS server for `.lan`, `.local` and
/// `bypass.domains` names and dial the upstream server itself, while every
/// other Windows process stays blocked from physical DNS.
pub const WEIGHT_PERMIT_SELF: u8 = 14;

/// Permit everything that leaves through the tunnel interface.
pub const WEIGHT_PERMIT_TUN: u8 = 13;

/// Permit DHCP and IPv6 neighbour discovery, which must work before a tunnel
/// exists and on interfaces the tunnel does not own.
pub const WEIGHT_PERMIT_BOOTSTRAP: u8 = 12;

/// Permit the configured bypass CIDRs and the server address.
///
/// The local DNS resolver is deliberately absent here: it is permitted for
/// this executable only through [`WEIGHT_PERMIT_LOCAL_DNS`], so other
/// processes cannot use it for plaintext port-53 queries.
pub const WEIGHT_PERMIT_CIDR: u8 = 10;

/// Permit this executable to reach the local DNS resolver on remote port 53.
///
/// Scoped with the same `ALE_APP_ID` condition as [`WEIGHT_PERMIT_SELF`], so
/// Windows Smart Multi-Homed Name Resolution in other processes still hits
/// [`WEIGHT_BLOCK_DNS`] and cannot wait on the physical resolver.
pub const WEIGHT_PERMIT_LOCAL_DNS: u8 = 6;

/// Block outbound DNS on any interface the permits do not cover.
pub const WEIGHT_BLOCK_DNS: u8 = 5;

/// Block every remaining outbound connection.
pub const WEIGHT_BLOCK_ALL: u8 = 0;

/// WFP timeout for starting and committing a transaction, in milliseconds.
///
/// A bounded wait keeps service start from hanging when another process holds
/// the engine transaction.
const TRANSACTION_TIMEOUT_MS: u32 = 10_000;

/// `RPC_C_AUTHN_WINNT`, the authentication service `FwpmEngineOpen0` expects
/// when the auth identity is null.
const RPC_C_AUTHN_WINNT: u32 = 10;

/// `IPPROTO_TCP` (`winsock2.h`).
const IPPROTO_TCP: u8 = 6;

/// `IPPROTO_UDP` (`winsock2.h`).
const IPPROTO_UDP: u8 = 17;

/// `IPPROTO_ICMPV6` (`winsock2.h`).
const IPPROTO_ICMPV6: u8 = 58;

/// `FWPM_CONDITION_ICMP_TYPE`; `fwpmu.h` defines it as an alias of
/// `FWPM_CONDITION_IP_LOCAL_PORT`, which carries the ICMP type when the IP
/// protocol is ICMP.
const CONDITION_ICMP_TYPE: GUID = FWPM_CONDITION_IP_LOCAL_PORT;

/// ICMPv6 Neighbor Discovery message types (`RFC 4861`) the guard lets through:
/// router solicitation (133), router advertisement (134), neighbour solicitation
/// (135), neighbour advertisement (136), and redirect (137). No other ICMPv6
/// type may leave a physical interface under the strict kill switch.
const ICMPV6_ND_TYPE_FIRST: u16 = 133;
const ICMPV6_ND_TYPE_LAST: u16 = 137;

/// DNS over UDP and TCP, the remote port Windows name resolution leaks on.
const DNS_PORT: u16 = 53;

/// DHCPv4 client and server ports.
const DHCPV4_CLIENT_PORT: u16 = 68;
const DHCPV4_SERVER_PORT: u16 = 67;

/// DHCPv6 client and server ports.
const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;

/// `FWP_E_ALREADY_EXISTS`: the sublayer key is already registered in this
/// dynamic session, which makes a rebuild idempotent.
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

/// What the guard must enforce.
#[derive(Clone, Debug)]
pub struct WfpConfig {
    /// LUID of the tunnel interface. Its traffic is always permitted.
    pub tun_luid: u64,
    /// Absolute path of the executable whose own connections are always
    /// permitted, so the tunnel can reach its server. [`WfpConfig::new`] fills
    /// this from the running image path (`GetModuleFileNameW` through
    /// `std::env::current_exe`).
    pub self_exe_path: PathBuf,
    /// Block unicast DNS to remote port 53 over UDP and TCP on every interface
    /// the permits do not cover, which defeats Windows Smart Multi-Homed Name
    /// Resolution leaks.
    ///
    /// Only port 53 is blocked here. LLMNR (UDP 5355), mDNS (UDP 5353) and
    /// NetBIOS name service (UDP 137) leak the same way, so they are blocked on
    /// physical interfaces only when [`WfpConfig::strict_kill_switch`] is also
    /// set, through its catch-all block.
    pub block_physical_dns: bool,
    /// Block every other outbound connection that does not leave through the
    /// tunnel, except loopback, this executable, DHCP, neighbour discovery, and
    /// [`WfpConfig::permit_cidrs`].
    pub strict_kill_switch: bool,
    /// Destinations that stay reachable outside the tunnel, such as the tunnel
    /// server or an IP form of a `bypass.domains` entry.
    ///
    /// The local DNS resolver must never appear here: a global entry would let
    /// every process send plaintext port-53 queries to the pre-VPN resolver.
    /// Use [`WfpConfig::local_dns_ips`] instead, which is scoped to this
    /// executable.
    pub permit_cidrs: Vec<(IpAddr, u8)>,
    /// Resolver IPs of the physical adapter that only this executable may
    /// reach on remote port 53 (UDP and TCP, one filter per address and
    /// protocol). Bypass-domain resolution uses the client's own sockets, so
    /// it keeps working while every other process stays blocked from the
    /// physical resolver by [`WEIGHT_BLOCK_DNS`].
    pub local_dns_ips: Vec<IpAddr>,
}

impl WfpConfig {
    /// Builds a config for `tun_luid` with DNS-leak blocking on and the strict
    /// kill switch off.
    pub fn new(tun_luid: u64) -> io::Result<Self> {
        Ok(Self {
            tun_luid,
            self_exe_path: std::env::current_exe()?,
            block_physical_dns: true,
            strict_kill_switch: false,
            permit_cidrs: Vec::new(),
            local_dns_ips: Vec::new(),
        })
    }
}

/// An installed dynamic WFP policy.
///
/// Dropping the guard closes the dynamic engine session, and Windows then
/// deletes the sublayer and every filter in it.
pub struct WfpGuard {
    engine: HANDLE,
    config: WfpConfig,
    app_id: *mut FWP_BYTE_BLOB,
    filter_ids: Vec<u64>,
}

impl WfpGuard {
    /// Installs the filters for `config` in one transaction.
    ///
    /// Nothing is enforced until the transaction commits; any failure aborts
    /// the transaction and leaves the machine unchanged.
    pub fn install(config: WfpConfig) -> io::Result<Self> {
        validate_config(&config)?;
        let engine = open_engine()?;
        // Errors after this point drop `guard`, whose `Drop` closes the engine
        // and frees the app ID, so no path leaks either.
        let mut guard = Self {
            engine,
            config,
            app_id: ptr::null_mut(),
            filter_ids: Vec::new(),
        };
        guard.app_id = resolve_app_id(&guard.config.self_exe_path)?;
        guard.rebuild()?;
        Ok(guard)
    }

    /// Replaces the bypass CIDRs, keeping the rest of the policy unchanged.
    ///
    /// On failure the previous filters and previous CIDR list stay in force.
    pub fn update_permit_cidrs(&mut self, cidrs: &[(IpAddr, u8)]) -> io::Result<()> {
        for entry in cidrs {
            validate_permit_cidr(entry)?;
        }
        let previous = std::mem::replace(&mut self.config.permit_cidrs, cidrs.to_vec());
        match self.rebuild() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.config.permit_cidrs = previous;
                Err(err)
            }
        }
    }

    /// Replaces the local DNS resolver IPs, keeping the rest unchanged.
    ///
    /// On failure the previous filters and previous resolver list stay in
    /// force.
    pub fn update_local_dns_ips(&mut self, ips: &[IpAddr]) -> io::Result<()> {
        let previous = std::mem::replace(&mut self.config.local_dns_ips, ips.to_vec());
        match self.rebuild() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.config.local_dns_ips = previous;
                Err(err)
            }
        }
    }

    /// Number of filters the last successful install added.
    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }

    /// Configuration the installed filters were built from.
    pub fn config(&self) -> &WfpConfig {
        &self.config
    }

    /// Replaces every filter in one transaction.
    fn rebuild(&mut self) -> io::Result<()> {
        self.begin_transaction()?;
        let filter_ids = match self.apply() {
            Ok(filter_ids) => filter_ids,
            Err(err) => {
                self.abort_transaction();
                return Err(err);
            }
        };
        match self.commit_transaction() {
            Ok(()) => {
                self.filter_ids = filter_ids;
                Ok(())
            }
            Err(err) => {
                self.abort_transaction();
                Err(err)
            }
        }
    }

    /// Rewrites the filter set. Runs inside the caller's transaction.
    fn apply(&self) -> io::Result<Vec<u64>> {
        for id in &self.filter_ids {
            // SAFETY: `id` was returned by `FwpmFilterAdd0` for a filter in the
            // dynamic session that owns `self.engine`, so the delete either
            // removes that filter or fails without touching other objects.
            let code = unsafe { FwpmFilterDeleteById0(self.engine, *id) };
            if code != 0 {
                return Err(wfp_error("FwpmFilterDeleteById0", code));
            }
        }
        self.add_sublayer()?;
        self.add_filters()
    }

    fn add_sublayer(&self) -> io::Result<()> {
        let name = wide_str("Beam tunnel guard")?;
        let description = wide_str("Beam DNS-leak and kill-switch filters")?;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: description.as_ptr().cast_mut(),
            },
            weight: u16::MAX,
            ..FWPM_SUBLAYER0::default()
        };
        // SAFETY: `sublayer` and both display strings live for the call, the
        // security-descriptor argument is NULL as documented, and the engine
        // handle is an open dynamic session owned by `self`.
        let code = unsafe { FwpmSubLayerAdd0(self.engine, &sublayer, ptr::null_mut()) };
        // A key that already exists (an earlier run in this dynamic session, or
        // a sublayer another instance registered) is reused: the filters beam
        // adds below still belong to this session and disappear with it.
        if code != 0 && code != FWP_E_ALREADY_EXISTS {
            return Err(wfp_error("FwpmSubLayerAdd0", code));
        }
        Ok(())
    }

    fn add_filters(&self) -> io::Result<Vec<u64>> {
        let planned = plan_filters(&self.config, self.app_id_condition()?)?;
        let mut ids = Vec::with_capacity(planned.len());
        for filter in planned {
            ids.push(self.add_filter(
                &filter.layer,
                filter.weight,
                filter.action,
                filter.name,
                &filter.conditions,
            )?);
        }
        Ok(ids)
    }

    /// Copies the resolved app ID into the blob a condition value points at.
    fn app_id_condition(&self) -> io::Result<FWP_BYTE_BLOB> {
        if self.app_id.is_null() {
            return Err(io::Error::other("WFP app ID is not resolved"));
        }
        // SAFETY: `self.app_id` comes from `FwpmGetAppIdFromFileName0`, stays
        // allocated until `Drop`, and the pointed-to blob is only read here.
        Ok(unsafe { *self.app_id })
    }

    fn add_filter(
        &self,
        layer: &GUID,
        weight: u8,
        action: FWP_ACTION_TYPE,
        name: &str,
        conditions: &[Condition],
    ) -> io::Result<u64> {
        let mut name_wide = wide_str(name)?;
        let mut raw: Vec<FWPM_FILTER_CONDITION0> =
            conditions.iter().map(Condition::to_wfp).collect();
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            layerKey: *layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: raw.len() as u32,
            filterCondition: if raw.is_empty() {
                ptr::null_mut()
            } else {
                raw.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::default(),
                },
            },
            ..FWPM_FILTER0::default()
        };
        let mut id = 0_u64;
        // SAFETY: `filter` points at `raw` and `name_wide`, both alive for the
        // call, the security-descriptor argument is NULL as documented, and the
        // engine handle is an open dynamic session owned by `self`.
        let code = unsafe { FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), &raw mut id) };
        if code != 0 {
            return Err(wfp_error("FwpmFilterAdd0", code));
        }
        Ok(id)
    }

    fn begin_transaction(&self) -> io::Result<()> {
        // SAFETY: the engine handle is an open dynamic session owned by `self`
        // and no other transaction is open on it.
        let code = unsafe { FwpmTransactionBegin0(self.engine, 0) };
        if code != 0 {
            return Err(wfp_error("FwpmTransactionBegin0", code));
        }
        Ok(())
    }

    fn commit_transaction(&self) -> io::Result<()> {
        // SAFETY: a transaction is open on this engine from
        // `begin_transaction`, and nothing else in this process uses the handle.
        let code = unsafe { FwpmTransactionCommit0(self.engine) };
        if code != 0 {
            return Err(wfp_error("FwpmTransactionCommit0", code));
        }
        Ok(())
    }

    fn abort_transaction(&self) {
        // SAFETY: a transaction is open on this engine, and aborting a
        // transaction that already failed to commit is documented and
        // harmless. A failed abort needs no recovery step because the
        // transaction cannot outlive the engine session.
        unsafe { FwpmTransactionAbort0(self.engine) };
    }
}

impl Drop for WfpGuard {
    fn drop(&mut self) {
        if !self.app_id.is_null() {
            let mut raw: *mut c_void = self.app_id.cast();
            // SAFETY: `app_id` was allocated by `FwpmGetAppIdFromFileName0` and
            // is freed exactly once here; `FwpmFreeMemory0` takes the address
            // of the pointer and takes ownership of the block.
            unsafe { FwpmFreeMemory0(&raw mut raw) };
            self.app_id = ptr::null_mut();
        }
        // SAFETY: `engine` is an open dynamic session owned by this value, so
        // closing it deletes the sublayer and every filter it holds.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

// SAFETY: a WFP engine handle names a kernel object: WFP accepts calls on it
// from any thread, and `Drop` runs on the owning thread after the last use.
unsafe impl Send for WfpGuard {}

/// One filter to install: everything `FwpmFilterAdd0` needs except a filter ID.
struct PlannedFilter {
    layer: GUID,
    weight: u8,
    action: FWP_ACTION_TYPE,
    name: &'static str,
    conditions: Vec<Condition>,
}

impl PlannedFilter {
    fn new(
        layer: GUID,
        weight: u8,
        action: FWP_ACTION_TYPE,
        name: &'static str,
        conditions: Vec<Condition>,
    ) -> Self {
        Self {
            layer,
            weight,
            action,
            name,
            conditions,
        }
    }
}

/// Builds the whole filter set for `config` without touching the WFP engine.
///
/// WFP rejects a filter that repeats a `fieldKey` with
/// `FWP_E_DUPLICATE_CONDITION`, so a set of destinations or protocols that must
/// Or together becomes one filter per member.
fn plan_filters(config: &WfpConfig, app_id: FWP_BYTE_BLOB) -> io::Result<Vec<PlannedFilter>> {
    let mut planned = Vec::new();
    if !config.block_physical_dns && !config.strict_kill_switch {
        return Ok(planned);
    }
    for (family, layer) in [
        (Family::V4, FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        (Family::V6, FWPM_LAYER_ALE_AUTH_CONNECT_V6),
    ] {
        planned.push(PlannedFilter::new(
            layer,
            WEIGHT_PERMIT_LOOPBACK,
            FWP_ACTION_PERMIT,
            "permit loopback",
            vec![Condition::flags(
                FWPM_CONDITION_FLAGS,
                FWP_CONDITION_FLAG_IS_LOOPBACK,
            )],
        ));
        planned.push(PlannedFilter::new(
            layer,
            WEIGHT_PERMIT_SELF,
            FWP_ACTION_PERMIT,
            "permit this executable",
            vec![Condition::byte_blob(FWPM_CONDITION_ALE_APP_ID, app_id)],
        ));
        planned.push(PlannedFilter::new(
            layer,
            WEIGHT_PERMIT_TUN,
            FWP_ACTION_PERMIT,
            "permit tunnel interface",
            vec![Condition::uint64(
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                config.tun_luid,
            )],
        ));
        if config.strict_kill_switch {
            push_bootstrap_filters(&mut planned, family, layer)?;
            push_cidr_filters(&mut planned, config, family, layer)?;
        }
        if config.block_physical_dns {
            push_local_dns_filters(&mut planned, config, family, layer, app_id)?;
            // DNS over UDP and DNS over TCP need one filter each: the protocol
            // condition may appear only once per filter.
            for (protocol, name) in [
                (
                    IPPROTO_UDP,
                    "block outbound DNS over UDP outside the tunnel",
                ),
                (
                    IPPROTO_TCP,
                    "block outbound DNS over TCP outside the tunnel",
                ),
            ] {
                planned.push(PlannedFilter::new(
                    layer,
                    WEIGHT_BLOCK_DNS,
                    FWP_ACTION_BLOCK,
                    name,
                    vec![
                        Condition::uint8(FWPM_CONDITION_IP_PROTOCOL, protocol),
                        Condition::uint16(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT),
                    ],
                ));
            }
        }
        if config.strict_kill_switch {
            planned.push(PlannedFilter::new(
                layer,
                WEIGHT_BLOCK_ALL,
                FWP_ACTION_BLOCK,
                "block all outbound traffic outside the tunnel",
                Vec::new(),
            ));
        }
    }
    Ok(planned)
}

/// Permits DHCP and, on IPv6, neighbour discovery.
///
/// Both protocols bind well-known ports and utilities, so the port pair alone
/// identifies DHCP. Neighbour discovery is limited to the five ICMPv6 ND types
/// and to the link-local unicast and link-scoped multicast destinations, which
/// cannot reach the internet.
fn push_bootstrap_filters(
    planned: &mut Vec<PlannedFilter>,
    family: Family,
    layer: GUID,
) -> io::Result<()> {
    match family {
        Family::V4 => planned.push(PlannedFilter::new(
            layer,
            WEIGHT_PERMIT_BOOTSTRAP,
            FWP_ACTION_PERMIT,
            "permit DHCPv4",
            vec![
                Condition::uint8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
                Condition::uint16(FWPM_CONDITION_IP_LOCAL_PORT, DHCPV4_CLIENT_PORT),
                Condition::uint16(FWPM_CONDITION_IP_REMOTE_PORT, DHCPV4_SERVER_PORT),
            ],
        )),
        Family::V6 => {
            planned.push(PlannedFilter::new(
                layer,
                WEIGHT_PERMIT_BOOTSTRAP,
                FWP_ACTION_PERMIT,
                "permit DHCPv6",
                vec![
                    Condition::uint8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
                    Condition::uint16(FWPM_CONDITION_IP_LOCAL_PORT, DHCPV6_CLIENT_PORT),
                    Condition::uint16(FWPM_CONDITION_IP_REMOTE_PORT, DHCPV6_SERVER_PORT),
                ],
            ));
            // One prefix per filter, because the remote-address condition may
            // appear only once.
            for (address, prefix, name) in [
                (
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
                    10_u8,
                    "permit IPv6 neighbour discovery from link-local unicast",
                ),
                (
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
                    16_u8,
                    "permit IPv6 neighbour discovery on link-scoped multicast",
                ),
            ] {
                planned.push(PlannedFilter::new(
                    layer,
                    WEIGHT_PERMIT_BOOTSTRAP,
                    FWP_ACTION_PERMIT,
                    name,
                    vec![
                        Condition::uint8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_ICMPV6),
                        Condition::uint16_range(
                            CONDITION_ICMP_TYPE,
                            ICMPV6_ND_TYPE_FIRST,
                            ICMPV6_ND_TYPE_LAST,
                        ),
                        Condition::v6_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, address, prefix)?,
                    ],
                ));
            }
        }
    }
    Ok(())
}

/// Permits the configured bypass CIDRs for one address family.
///
/// Each CIDR becomes its own single-condition filter, so the guard can delete
/// every ID it created when the CIDRs change.
fn push_cidr_filters(
    planned: &mut Vec<PlannedFilter>,
    config: &WfpConfig,
    family: Family,
    layer: GUID,
) -> io::Result<()> {
    for (address, prefix) in &config.permit_cidrs {
        let condition = match (family, address) {
            (Family::V4, IpAddr::V4(address)) => {
                Condition::v4_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *address, *prefix)?
            }
            (Family::V6, IpAddr::V6(address)) => {
                Condition::v6_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *address, *prefix)?
            }
            _ => continue,
        };
        planned.push(PlannedFilter::new(
            layer,
            WEIGHT_PERMIT_CIDR,
            FWP_ACTION_PERMIT,
            "permit bypass destination",
            vec![condition],
        ));
    }
    Ok(())
}

/// Permits only this executable to reach the local DNS resolver on port 53.
///
/// Each resolver IP becomes one UDP and one TCP filter scoped with the
/// `ALE_APP_ID` condition, because a field key cannot repeat inside one
/// filter and one filter cannot cover both protocols. The weight outranks
/// [`WEIGHT_BLOCK_DNS`], so the client's own bypass-domain resolutions keep
/// working while every other process stays blocked from the physical
/// resolver.
fn push_local_dns_filters(
    planned: &mut Vec<PlannedFilter>,
    config: &WfpConfig,
    family: Family,
    layer: GUID,
    app_id: FWP_BYTE_BLOB,
) -> io::Result<()> {
    for ip in &config.local_dns_ips {
        for (protocol, name) in [
            (IPPROTO_UDP, "permit this executable to local DNS over UDP"),
            (IPPROTO_TCP, "permit this executable to local DNS over TCP"),
        ] {
            // One filter per address and protocol: a field key cannot repeat
            // inside one filter.
            let remote = match (family, ip) {
                (Family::V4, IpAddr::V4(address)) => {
                    Condition::v4_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *address, 32)?
                }
                (Family::V6, IpAddr::V6(address)) => {
                    Condition::v6_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *address, 128)?
                }
                _ => continue,
            };
            planned.push(PlannedFilter::new(
                layer,
                WEIGHT_PERMIT_LOCAL_DNS,
                FWP_ACTION_PERMIT,
                name,
                vec![
                    Condition::byte_blob(FWPM_CONDITION_ALE_APP_ID, app_id),
                    Condition::uint8(FWPM_CONDITION_IP_PROTOCOL, protocol),
                    Condition::uint16(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT),
                    remote,
                ],
            ));
        }
    }
    Ok(())
}

/// IPv4 or IPv6 outbound layer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// One WFP filter condition whose value lives in the box behind it.
struct Condition {
    field: GUID,
    match_type: FWP_MATCH_TYPE,
    value: Box<Value>,
}

impl Condition {
    fn uint8(field: GUID, value: u8) -> Self {
        Self::new(field, Value::Uint8(value))
    }

    fn uint16(field: GUID, value: u16) -> Self {
        Self::new(field, Value::Uint16(value))
    }

    fn uint64(field: GUID, value: u64) -> Self {
        Self::new(field, Value::Uint64(value))
    }

    /// Accepts a closed range, which WFP matches with `FWP_MATCH_RANGE`.
    fn uint16_range(field: GUID, low: u16, high: u16) -> Self {
        Self {
            field,
            match_type: FWP_MATCH_RANGE,
            value: Box::new(Value::Uint16Range(FWP_RANGE0 {
                valueLow: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: low },
                },
                valueHigh: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: high },
                },
            })),
        }
    }

    fn flags(field: GUID, value: u32) -> Self {
        Self {
            field,
            match_type: FWP_MATCH_FLAGS_ALL_SET,
            value: Box::new(Value::Uint32(value)),
        }
    }

    fn byte_blob(field: GUID, value: FWP_BYTE_BLOB) -> Self {
        Self::new(field, Value::ByteBlob(value))
    }

    fn v4_mask(field: GUID, address: Ipv4Addr, prefix: u8) -> io::Result<Self> {
        let mask = prefix_to_v4_mask(prefix).ok_or_else(|| invalid_prefix("IPv4", prefix, 32))?;
        Ok(Self::new(
            field,
            Value::V4Mask(FWP_V4_ADDR_AND_MASK {
                addr: u32::from(address) & mask,
                mask,
            }),
        ))
    }

    fn v6_mask(field: GUID, address: Ipv6Addr, prefix: u8) -> io::Result<Self> {
        let mask = prefix_to_v6_bytes(prefix).ok_or_else(|| invalid_prefix("IPv6", prefix, 128))?;
        let mut octets = address.octets();
        for (octet, mask) in octets.iter_mut().zip(mask) {
            *octet &= mask;
        }
        Ok(Self::new(
            field,
            Value::V6Mask(FWP_V6_ADDR_AND_MASK {
                addr: octets,
                prefixLength: prefix,
            }),
        ))
    }

    fn new(field: GUID, value: Value) -> Self {
        Self {
            field,
            match_type: FWP_MATCH_EQUAL,
            value: Box::new(value),
        }
    }

    fn to_wfp(&self) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: self.field,
            matchType: self.match_type,
            conditionValue: self.value.to_wfp(),
        }
    }
}

/// A condition value whose pointers stay valid as long as the boxed value does.
enum Value {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    ByteBlob(FWP_BYTE_BLOB),
    V4Mask(FWP_V4_ADDR_AND_MASK),
    V6Mask(FWP_V6_ADDR_AND_MASK),
    Uint16Range(FWP_RANGE0),
}

impl Value {
    fn to_wfp(&self) -> FWP_CONDITION_VALUE0 {
        // SAFETY: every pointer handed to WFP points at a field of `*self`,
        // which the owning `Condition` box keeps at a stable address for the
        // whole `FwpmFilterAdd0` call. WFP only reads through them.
        match self {
            Self::Uint8(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *value },
            },
            Self::Uint16(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *value },
            },
            Self::Uint32(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: *value },
            },
            Self::Uint64(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: ptr::from_ref(value).cast_mut(),
                },
            },
            Self::ByteBlob(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: ptr::from_ref(value).cast_mut(),
                },
            },
            Self::V4Mask(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: ptr::from_ref(value).cast_mut(),
                },
            },
            Self::V6Mask(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: ptr::from_ref(value).cast_mut(),
                },
            },
            Self::Uint16Range(value) => FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: ptr::from_ref(value).cast_mut(),
                },
            },
        }
    }
}

/// Converts an IPv4 prefix length into a contiguous mask.
///
/// The mask shares the byte order of `u32::from(Ipv4Addr)`, so masking an
/// address with it clears the host bits WFP should ignore.
pub fn prefix_to_v4_mask(prefix: u8) -> Option<u32> {
    match prefix {
        0 => Some(0),
        1..=32 => Some(u32::MAX << (32 - u32::from(prefix))),
        _ => None,
    }
}

/// Converts an IPv6 prefix length into a contiguous 16-byte mask.
pub fn prefix_to_v6_bytes(prefix: u8) -> Option<[u8; 16]> {
    if prefix > 128 {
        return None;
    }
    let mut mask = [0_u8; 16];
    for (index, byte) in mask.iter_mut().enumerate() {
        let bits = (prefix.saturating_sub(index as u8 * 8)).min(8);
        if bits > 0 {
            *byte = 0xff_u8 << (8 - bits);
        }
    }
    Some(mask)
}

/// Opens a dynamic WFP engine session.
fn open_engine() -> io::Result<HANDLE> {
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txnWaitTimeoutInMSec: TRANSACTION_TIMEOUT_MS,
        ..FWPM_SESSION0::default()
    };
    let mut engine: HANDLE = ptr::null_mut();
    // SAFETY: the engine writes one handle through `engine`, the session
    // structure and every pointer in it are valid for the call, and a null
    // server name and auth identity select the local engine with the caller's
    // own credentials, as documented.
    let code = unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            &session,
            &mut engine,
        )
    };
    if code != 0 {
        return Err(wfp_error("FwpmEngineOpen0", code));
    }
    if engine.is_null() {
        return Err(io::Error::other(
            "FwpmEngineOpen0 succeeded with a null engine handle",
        ));
    }
    Ok(engine)
}

/// Resolves the app ID that identifies an executable to WFP.
fn resolve_app_id(path: &Path) -> io::Result<*mut FWP_BYTE_BLOB> {
    let path_wide = wide_os_str(path.as_os_str())?;
    let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
    // SAFETY: the file name is NUL-terminated and lives for the call, and WFP
    // writes one allocated blob pointer through `app_id`.
    let code = unsafe { FwpmGetAppIdFromFileName0(path_wide.as_ptr(), &mut app_id) };
    if code != 0 {
        return Err(wfp_error("FwpmGetAppIdFromFileName0", code));
    }
    if app_id.is_null() {
        return Err(io::Error::other(
            "FwpmGetAppIdFromFileName0 returned a null blob",
        ));
    }
    Ok(app_id)
}

/// Rejects a config the filters cannot express.
fn validate_config(config: &WfpConfig) -> io::Result<()> {
    if config.tun_luid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WFP guard needs a non-zero tunnel LUID",
        ));
    }
    if !config.self_exe_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "WFP guard needs an absolute executable path, got {}",
                config.self_exe_path.display()
            ),
        ));
    }
    for entry in &config.permit_cidrs {
        validate_permit_cidr(entry)?;
    }
    Ok(())
}

/// Rejects a bypass entry whose prefix length exceeds its address family.
fn validate_permit_cidr(entry: &(IpAddr, u8)) -> io::Result<()> {
    let (address, prefix) = entry;
    let limit = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if *prefix > limit {
        return Err(invalid_prefix("bypass", *prefix, limit));
    }
    Ok(())
}

fn invalid_prefix(what: &str, prefix: u8, limit: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{what} prefix length must be at most {limit}, got {prefix}"),
    )
}

/// Builds the error for a WFP call that returned `code`.
fn wfp_error(operation: &str, code: u32) -> io::Error {
    let source = io::Error::from_raw_os_error(code as i32);
    io::Error::new(
        source.kind(),
        format!("{operation} failed with WFP error {code:#x} ({source})"),
    )
}

/// Encodes a string as NUL-terminated UTF-16.
fn wide_str(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "display name must not contain NUL",
        ));
    }
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    Ok(wide)
}

/// Encodes a path as NUL-terminated UTF-16.
fn wide_os_str(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must not contain NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::{
        CONDITION_ICMP_TYPE, Condition, FWP_BYTE_BLOB, FWP_MATCH_RANGE, FWP_UINT16, IpAddr,
        Ipv4Addr, Ipv6Addr, MAX_FILTER_WEIGHT, PathBuf, SUBLAYER_KEY, Value, WEIGHT_BLOCK_ALL,
        WEIGHT_BLOCK_DNS, WEIGHT_PERMIT_BOOTSTRAP, WEIGHT_PERMIT_CIDR, WEIGHT_PERMIT_LOCAL_DNS,
        WEIGHT_PERMIT_LOOPBACK, WEIGHT_PERMIT_SELF, WEIGHT_PERMIT_TUN, WfpConfig, plan_filters,
        prefix_to_v4_mask, prefix_to_v6_bytes, validate_config, validate_permit_cidr,
    };

    #[test]
    fn ipv4_masks_are_contiguous() {
        assert_eq!(prefix_to_v4_mask(0), Some(0));
        assert_eq!(prefix_to_v4_mask(8), Some(0xff00_0000));
        assert_eq!(prefix_to_v4_mask(24), Some(0xffff_ff00));
        assert_eq!(prefix_to_v4_mask(32), Some(0xffff_ffff));
        assert_eq!(prefix_to_v4_mask(33), None);
    }

    #[test]
    fn ipv6_masks_are_contiguous() {
        assert_eq!(prefix_to_v6_bytes(0), Some([0; 16]));
        assert_eq!(prefix_to_v6_bytes(128), Some([0xff; 16]));
        assert_eq!(prefix_to_v6_bytes(129), None);

        let link_local = prefix_to_v6_bytes(10).expect("fe80::/10 mask");
        assert_eq!(&link_local[..2], &[0xff, 0xc0]);
        assert!(link_local[2..].iter().all(|byte| *byte == 0));

        let single_bit = prefix_to_v6_bytes(1).expect("/1 mask");
        assert_eq!(single_bit[0], 0x80);
        assert!(single_bit[1..].iter().all(|byte| *byte == 0));

        // Every mask stays contiguous: no zero byte before a set byte.
        for prefix in 0..=128_u8 {
            let mask = prefix_to_v6_bytes(prefix).expect("valid prefix");
            let bits: Vec<bool> = mask
                .iter()
                .flat_map(|byte| (0..8).map(move |shift| byte & (0x80 >> shift) != 0))
                .collect();
            let first_zero = bits.iter().position(|bit| !bit).unwrap_or(bits.len());
            assert!(
                bits[first_zero..].iter().all(|bit| !bit),
                "prefix {prefix} produced a non-contiguous mask"
            );
        }
    }

    #[test]
    fn cidr_conditions_normalise_host_bits() {
        let v4 = Condition::v4_mask(
            super::FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Ipv4Addr::new(192, 168, 1, 5),
            24,
        )
        .expect("v4 condition");
        let Value::V4Mask(mask) = *v4.value else {
            panic!("v4 condition must carry a v4 mask");
        };
        assert_eq!(mask.addr, u32::from(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(mask.mask, 0xffff_ff00);

        // /32 keeps the whole address, so one server address stays reachable.
        let host = Condition::v4_mask(
            super::FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Ipv4Addr::new(203, 0, 113, 7),
            32,
        )
        .expect("host condition");
        let Value::V4Mask(mask) = *host.value else {
            panic!("host condition must carry a v4 mask");
        };
        assert_eq!(mask.addr, u32::from(Ipv4Addr::new(203, 0, 113, 7)));

        let v6 = Condition::v6_mask(
            super::FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
            10,
        )
        .expect("v6 condition");
        let Value::V6Mask(mask) = *v6.value else {
            panic!("v6 condition must carry a v6 mask");
        };
        assert_eq!(&mask.addr[..2], &[0xfe, 0x80]);
        assert!(mask.addr[2..].iter().all(|byte| *byte == 0));
        assert_eq!(mask.prefixLength, 10);
    }

    #[test]
    fn planned_filters_never_repeat_a_condition_field() {
        let config = WfpConfig {
            tun_luid: 0x0000_0001_0000_0001,
            self_exe_path: PathBuf::from("C:\\Program Files\\beam\\beam-client.exe"),
            block_physical_dns: true,
            strict_kill_switch: true,
            permit_cidrs: vec![
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24),
                (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 32),
                (
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    128,
                ),
            ],
            local_dns_ips: vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            ],
        };
        // Planning only copies the blob; WFP never reads it here.
        let app_id = FWP_BYTE_BLOB {
            size: 0,
            data: std::ptr::null_mut(),
        };
        let planned = plan_filters(&config, app_id).expect("filter plan");

        for filter in &planned {
            let mut fields: Vec<(u32, u16, u16, [u8; 8])> = filter
                .conditions
                .iter()
                .map(|condition| {
                    let key = condition.field;
                    (key.data1, key.data2, key.data3, key.data4)
                })
                .collect();
            let total = fields.len();
            fields.sort();
            fields.dedup();
            assert_eq!(
                fields.len(),
                total,
                "filter {:?} repeats a fieldKey, which WFP rejects with \
                 FWP_E_DUPLICATE_CONDITION",
                filter.name
            );
        }

        assert_eq!(
            planned
                .iter()
                .filter(|filter| filter.weight == WEIGHT_PERMIT_CIDR)
                .count(),
            config.permit_cidrs.len(),
            "every bypass CIDR needs its own single-condition filter"
        );

        // The resolver permits are derived, not hardcoded: one UDP and one TCP
        // filter per resolver IP.
        assert_eq!(
            planned
                .iter()
                .filter(|filter| filter.weight == WEIGHT_PERMIT_LOCAL_DNS)
                .count(),
            config.local_dns_ips.len() * 2,
            "every resolver IP needs one UDP and one TCP app-scoped permit"
        );
    }

    #[test]
    fn neighbour_discovery_permits_only_nd_icmpv6_types() {
        let config = WfpConfig {
            tun_luid: 0x0000_0001_0000_0001,
            self_exe_path: PathBuf::from("C:\\Program Files\\beam\\beam-client.exe"),
            block_physical_dns: true,
            strict_kill_switch: true,
            permit_cidrs: Vec::new(),
            local_dns_ips: Vec::new(),
        };
        let app_id = FWP_BYTE_BLOB {
            size: 0,
            data: std::ptr::null_mut(),
        };
        let planned = plan_filters(&config, app_id).expect("filter plan");
        let neighbour: Vec<_> = planned
            .iter()
            .filter(|filter| filter.name.contains("neighbour"))
            .collect();
        assert_eq!(neighbour.len(), 2, "one prefix per neighbour filter");

        for filter in neighbour {
            let condition = filter
                .conditions
                .iter()
                .find(|condition| {
                    let key = condition.field;
                    (key.data1, key.data2, key.data3, key.data4)
                        == (
                            CONDITION_ICMP_TYPE.data1,
                            CONDITION_ICMP_TYPE.data2,
                            CONDITION_ICMP_TYPE.data3,
                            CONDITION_ICMP_TYPE.data4,
                        )
                })
                .expect("neighbour discovery must be limited to ICMPv6 ND types");
            assert_eq!(condition.match_type, FWP_MATCH_RANGE);
            let Value::Uint16Range(range) = *condition.value else {
                panic!("ICMP type must be a uint16 range");
            };
            assert_eq!(range.valueLow.r#type, FWP_UINT16);
            assert_eq!(range.valueHigh.r#type, FWP_UINT16);
            // SAFETY: both union members hold the `u16` that `uint16_range`
            // wrote, and the type fields above say so.
            let (low, high) = unsafe {
                (
                    range.valueLow.Anonymous.uint16,
                    range.valueHigh.Anonymous.uint16,
                )
            };
            assert_eq!((low, high), (133, 137), "RFC 4861 ND types only");
        }
    }

    #[test]
    fn permit_cidrs_reject_out_of_range_prefixes() {
        assert!(validate_permit_cidr(&(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)).is_ok());
        assert!(validate_permit_cidr(&(IpAddr::V4(Ipv4Addr::LOCALHOST), 33)).is_err());
        assert!(validate_permit_cidr(&(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)).is_ok());
        assert!(validate_permit_cidr(&(IpAddr::V6(Ipv6Addr::LOCALHOST), 129)).is_err());
    }

    #[test]
    fn filter_weights_keep_every_permit_above_every_block() {
        let permits = [
            WEIGHT_PERMIT_LOOPBACK,
            WEIGHT_PERMIT_SELF,
            WEIGHT_PERMIT_TUN,
            WEIGHT_PERMIT_BOOTSTRAP,
            WEIGHT_PERMIT_CIDR,
            WEIGHT_PERMIT_LOCAL_DNS,
        ];
        let blocks = [WEIGHT_BLOCK_DNS, WEIGHT_BLOCK_ALL];

        assert!(permits.windows(2).all(|pair| pair[0] > pair[1]));
        assert!(blocks.windows(2).all(|pair| pair[0] > pair[1]));
        assert!(
            permits.iter().min() > blocks.iter().max(),
            "a block must never outrank a permit"
        );
        assert!(
            permits
                .iter()
                .chain(blocks.iter())
                .all(|w| *w <= MAX_FILTER_WEIGHT)
        );
    }

    #[test]
    fn sublayer_key_is_a_valid_non_zero_guid() {
        let key = SUBLAYER_KEY;
        assert_ne!(
            (key.data1, key.data2, key.data3, key.data4),
            (0, 0, 0, [0; 8]),
            "the sublayer key must not be the nil GUID"
        );
        assert_eq!(key.data3 >> 12, 4, "RFC 4122 version 4 layout");
        assert_eq!(key.data4[0] >> 6, 0b10, "RFC 4122 variant");
    }

    #[test]
    fn config_validation_rejects_unusable_luid_and_paths() {
        let mut config = WfpConfig {
            tun_luid: 0,
            self_exe_path: PathBuf::from("relative\\beam-client.exe"),
            block_physical_dns: true,
            strict_kill_switch: false,
            permit_cidrs: Vec::new(),
            local_dns_ips: Vec::new(),
        };
        assert!(validate_config(&config).is_err(), "zero LUID must fail");

        config.tun_luid = 0x0000_0001_0000_0001;
        assert!(validate_config(&config).is_err(), "relative path must fail");

        config.self_exe_path = PathBuf::from("C:\\Program Files\\beam\\beam-client.exe");
        config
            .permit_cidrs
            .push((IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 32));
        assert!(validate_config(&config).is_ok());

        config
            .permit_cidrs
            .push((IpAddr::V6(Ipv6Addr::LOCALHOST), 129));
        assert!(validate_config(&config).is_err(), "bad prefix must fail");
    }

    fn has_field(filter: &super::PlannedFilter, field: &windows_sys::core::GUID) -> bool {
        filter.conditions.iter().any(|condition| {
            (
                condition.field.data1,
                condition.field.data2,
                condition.field.data3,
                condition.field.data4,
            ) == (field.data1, field.data2, field.data3, field.data4)
        })
    }

    fn protocol_of(filter: &super::PlannedFilter) -> Option<u8> {
        filter.conditions.iter().find_map(|condition| {
            let same = (
                condition.field.data1,
                condition.field.data2,
                condition.field.data3,
                condition.field.data4,
            ) == (
                super::FWPM_CONDITION_IP_PROTOCOL.data1,
                super::FWPM_CONDITION_IP_PROTOCOL.data2,
                super::FWPM_CONDITION_IP_PROTOCOL.data3,
                super::FWPM_CONDITION_IP_PROTOCOL.data4,
            );
            if !same {
                return None;
            }
            match *condition.value {
                Value::Uint8(protocol) => Some(protocol),
                _ => None,
            }
        })
    }

    fn remote_port_of(filter: &super::PlannedFilter) -> Option<u16> {
        filter.conditions.iter().find_map(|condition| {
            let same = (
                condition.field.data1,
                condition.field.data2,
                condition.field.data3,
                condition.field.data4,
            ) == (
                super::FWPM_CONDITION_IP_REMOTE_PORT.data1,
                super::FWPM_CONDITION_IP_REMOTE_PORT.data2,
                super::FWPM_CONDITION_IP_REMOTE_PORT.data3,
                super::FWPM_CONDITION_IP_REMOTE_PORT.data4,
            );
            if !same {
                return None;
            }
            match *condition.value {
                Value::Uint16(port) => Some(port),
                _ => None,
            }
        })
    }

    fn remote_host_of(filter: &super::PlannedFilter) -> Option<IpAddr> {
        filter.conditions.iter().find_map(|condition| {
            let same = (
                condition.field.data1,
                condition.field.data2,
                condition.field.data3,
                condition.field.data4,
            ) == (
                super::FWPM_CONDITION_IP_REMOTE_ADDRESS.data1,
                super::FWPM_CONDITION_IP_REMOTE_ADDRESS.data2,
                super::FWPM_CONDITION_IP_REMOTE_ADDRESS.data3,
                super::FWPM_CONDITION_IP_REMOTE_ADDRESS.data4,
            );
            if !same {
                return None;
            }
            match *condition.value {
                Value::V4Mask(mask) if mask.mask == 0xffff_ffff => {
                    Some(IpAddr::V4(Ipv4Addr::from(mask.addr)))
                }
                Value::V6Mask(mask) if mask.prefixLength == 128 => {
                    Some(IpAddr::V6(Ipv6Addr::from(mask.addr)))
                }
                _ => None,
            }
        })
    }

    #[test]
    fn local_dns_permit_is_app_scoped_udp_and_tcp() {
        let dns_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dns_v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        // Strict mode off isolates the DNS path from the CIDR path: any
        // resolver permit here must come from `local_dns_ips`.
        let config = WfpConfig {
            tun_luid: 0x0000_0001_0000_0001,
            self_exe_path: PathBuf::from("C:\\Program Files\\beam\\beam-client.exe"),
            block_physical_dns: true,
            strict_kill_switch: false,
            permit_cidrs: Vec::new(),
            local_dns_ips: vec![dns_v4, dns_v6],
        };
        let app_id = FWP_BYTE_BLOB {
            size: 0,
            data: std::ptr::null_mut(),
        };
        let planned = plan_filters(&config, app_id).expect("filter plan");
        let dns_filters: Vec<_> = planned
            .iter()
            .filter(|filter| filter.weight == WEIGHT_PERMIT_LOCAL_DNS)
            .collect();
        // Derived, not hardcoded: one UDP and one TCP filter per resolver.
        assert_eq!(
            dns_filters.len(),
            config.local_dns_ips.len() * 2,
            "one UDP and one TCP permit per resolver IP"
        );
        assert!(
            dns_filters
                .iter()
                .all(|filter| filter.weight > WEIGHT_BLOCK_DNS),
            "the resolver permit must outrank the DNS block"
        );
        for ip in &config.local_dns_ips {
            for protocol in [super::IPPROTO_UDP, super::IPPROTO_TCP] {
                let found = dns_filters.iter().any(|filter| {
                    protocol_of(filter) == Some(protocol)
                        && remote_port_of(filter) == Some(super::DNS_PORT)
                        && remote_host_of(filter) == Some(*ip)
                        && has_field(filter, &super::FWPM_CONDITION_ALE_APP_ID)
                });
                assert!(
                    found,
                    "missing app-scoped {ip} permit for protocol {protocol}"
                );
            }
        }
        // Every resolver permit must carry the app-ID condition: without it
        // any process could use the physical resolver.
        for filter in &dns_filters {
            assert!(
                has_field(filter, &super::FWPM_CONDITION_ALE_APP_ID),
                "resolver permit {:?} lost its app-ID condition",
                filter.name
            );
        }
    }

    #[test]
    fn local_dns_has_no_global_cidr_permit() {
        let dns_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let config = WfpConfig {
            tun_luid: 0x0000_0001_0000_0001,
            self_exe_path: PathBuf::from("C:\\Program Files\\beam\\beam-client.exe"),
            block_physical_dns: true,
            strict_kill_switch: true,
            permit_cidrs: vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 32)],
            local_dns_ips: vec![dns_ip],
        };
        let app_id = FWP_BYTE_BLOB {
            size: 0,
            data: std::ptr::null_mut(),
        };
        let planned = plan_filters(&config, app_id).expect("filter plan");
        // A global CIDR permit for the resolver would let every process send
        // plaintext port-53 queries; the resolver must only appear in
        // app-scoped filters.
        for filter in planned
            .iter()
            .filter(|filter| filter.weight == WEIGHT_PERMIT_CIDR)
        {
            assert_ne!(
                remote_host_of(filter),
                Some(dns_ip),
                "resolver {dns_ip} must not have a global CIDR permit"
            );
        }
        // Any permit filter that names the resolver must be app-scoped.
        for filter in planned.iter().filter(|filter| {
            remote_host_of(filter) == Some(dns_ip) && filter.weight != WEIGHT_BLOCK_DNS
        }) {
            assert!(
                has_field(filter, &super::FWPM_CONDITION_ALE_APP_ID),
                "resolver permit {:?} must be scoped to this executable",
                filter.name
            );
        }
    }
}
