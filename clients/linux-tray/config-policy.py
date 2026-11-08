#!/usr/bin/env python3
"""Normalize a stock sing-box client profile's QUIC policy.

The default stock-client policy is private destinations direct, then a
pre-match public UDP/443 reject, then sniffing, then DNS hijack. The reject
must precede sniff so sing-box can synthesize ICMP port unreachable.
"""
import json
import sys


# sing-box rejects a string port (route rules take Listable[uint16]); accept
# any shape so an invalid profile fails at `sing-box check`, not here.
def _is_exact_udp_443_port(raw: object) -> bool:
    if isinstance(raw, int):
        return raw == 443
    if isinstance(raw, list):
        return len(raw) == 1 and raw[0] == 443
    if isinstance(raw, str):
        return raw.strip() == "443"
    return False


def is_udp443_reject(rule: dict) -> bool:
    return (
        rule.get("action") == "reject"
        and rule.get("network") == "udp"
        and _is_exact_udp_443_port(rule.get("port"))
    )


def _is_ipv6_literal(value: object) -> bool:
    return isinstance(value, str) and ":" in value


def ensure_ipv4_only(config: dict) -> None:
    dns = config.setdefault("dns", {})
    dns["strategy"] = "ipv4_only"

    for server in dns.get("servers", []):
        predefined = server.get("predefined") if isinstance(server, dict) else None
        if isinstance(predefined, dict):
            for host, addresses in list(predefined.items()):
                if isinstance(addresses, str):
                    predefined[host] = [] if _is_ipv6_literal(addresses) else [addresses]
                elif isinstance(addresses, list):
                    predefined[host] = [
                        address for address in addresses
                        if not _is_ipv6_literal(address)
                    ]

    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict) or inbound.get("type") != "tun":
            continue
        addresses = inbound.get("address", [])
        if isinstance(addresses, str):
            addresses = [addresses]
        if not isinstance(addresses, list):
            continue
        kept = [address for address in addresses if not _is_ipv6_literal(address)]
        if not kept:
            raise ValueError("TUN inbound has no IPv4 address")
        inbound["address"] = kept

    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules = [
        rule for rule in rules
        if not (
            isinstance(rule, dict)
            and str(rule.get("ip_version")) == "6"
            and rule.get("action") == "reject"
        )
    ]
    route["rules"] = [{"ip_version": 6, "action": "reject"}, *rules]


def normalize(config: dict) -> None:
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    private = next((r for r in rules if r.get("ip_is_private") is True), None)
    sniff = next((r for r in rules if r.get("action") == "sniff"), None)
    dns = next((r for r in rules if r.get("protocol") == "dns"), None)
    reject = {
        "action": "reject",
        "network": "udp",
        "port": [443],
        "method": "default",
        "no_drop": True,
    }
    others = [
        r
        for r in rules
        if r is not private
        and r is not sniff
        and r is not dns
        and not is_udp443_reject(r)
    ]
    route["rules"] = [r for r in (private, reject, sniff, dns) if r is not None] + others
    ensure_ipv4_only(config)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: config-policy.py INPUT OUTPUT", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as source:
        config = json.load(source)
    normalize(config)
    with open(sys.argv[2], "w", encoding="utf-8") as target:
        json.dump(config, target, indent=2)
        target.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
