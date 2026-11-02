#!/usr/bin/env python3
"""Normalize a stock sing-box client profile's QUIC policy.

The default stock-client policy is private destinations direct, then a
pre-match public UDP/443 reject, then sniffing, then DNS hijack. The reject
must precede sniff so sing-box can synthesize ICMP port unreachable.
"""
import json
import sys


def is_udp443_reject(rule: dict) -> bool:
    port = rule.get("port", [])
    if isinstance(port, int):
        port = [port]
    return (
        rule.get("action") == "reject"
        and rule.get("network") == "udp"
        and 443 in port
    )


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
