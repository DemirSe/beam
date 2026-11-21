#!/usr/bin/env python3
"""Focused regression tests for the IPv4-only Linux client normalizer."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _config(tun_address: object, predefined: object) -> dict:
    return {
        "dns": {
            "servers": [{"predefined": {"dns.example": predefined}}],
            "strategy": "prefer_ipv4",
        },
        "inbounds": [{"type": "tun", "address": tun_address}],
        "route": {"rules": [{"ip_is_private": True, "outbound": "direct"}]},
    }


class IPv4OnlyNormalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = _load("config_policy", ROOT / "clients/linux-tray/config-policy.py")

    def test_scalar_ipv6_bootstrap_is_removed(self):
        config = _config("172.19.0.1/30", "2606:1a40::22")
        self.policy.ensure_ipv4_only(config)
        self.assertEqual(config["dns"]["servers"][0]["predefined"]["dns.example"], [])
        self.assertEqual(config["dns"]["strategy"], "ipv4_only")

    def test_scalar_ipv4_values_are_normalized_to_lists(self):
        config = _config("172.19.0.1/30", "192.0.2.53")
        self.policy.ensure_ipv4_only(config)
        self.assertEqual(
            config["dns"]["servers"][0]["predefined"]["dns.example"],
            ["192.0.2.53"],
        )
        self.assertEqual(
            config["inbounds"][0]["address"],
            ["172.19.0.1/30"],
        )

    def test_scalar_ipv6_only_tun_is_rejected(self):
        config = _config("fdfe:dcba:9876::1/126", "192.0.2.53")
        with self.assertRaisesRegex(ValueError, "no IPv4 address"):
            self.policy.ensure_ipv4_only(config)

    def test_mixed_list_is_filtered_and_idempotent(self):
        config = _config(
            ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            ["192.0.2.53", "2606:1a40::22"],
        )
        self.policy.ensure_ipv4_only(config)
        self.policy.ensure_ipv4_only(config)
        self.assertEqual(
            config["inbounds"][0]["address"],
            ["172.19.0.1/30"],
        )
        self.assertEqual(
            config["dns"]["servers"][0]["predefined"]["dns.example"],
            ["192.0.2.53"],
        )
        self.assertEqual(
            config["route"]["rules"][0],
            {"ip_version": 6, "action": "reject"},
        )

    def test_empty_tun_address_array_is_rejected(self):
        config = _config([], "192.0.2.53")
        with self.assertRaisesRegex(ValueError, "no IPv4 address"):
            self.policy.ensure_ipv4_only(config)

    def test_ipv6_only_tun_array_is_rejected(self):
        config = _config(["fdfe:dcba:9876::1/126"], "192.0.2.53")
        with self.assertRaisesRegex(ValueError, "no IPv4 address"):
            self.policy.ensure_ipv4_only(config)

    def test_ipv6_only_dns_array_is_emptied(self):
        config = _config(
            "172.19.0.1/30",
            ["2606:1a40::22", "2606:1a40::23"],
        )
        self.policy.ensure_ipv4_only(config)
        self.assertEqual(
            config["dns"]["servers"][0]["predefined"]["dns.example"],
            [],
        )

    def test_multiple_tun_inbounds_keep_ipv4_and_reject_ipv6_only(self):
        config = _config("172.19.0.1/30", "192.0.2.53")
        config["inbounds"].append(
            {"type": "tun", "address": ["172.20.0.1/30", "fdfe:dcba:9876::1/126"]}
        )
        self.policy.ensure_ipv4_only(config)
        self.assertEqual(config["inbounds"][0]["address"], ["172.19.0.1/30"])
        self.assertEqual(config["inbounds"][1]["address"], ["172.20.0.1/30"])

        rejected = _config("172.19.0.1/30", "192.0.2.53")
        rejected["inbounds"].append(
            {"type": "tun", "address": ["fdfe:dcba:9876::1/126"]}
        )
        with self.assertRaisesRegex(ValueError, "no IPv4 address"):
            self.policy.ensure_ipv4_only(rejected)

    def test_existing_ipv6_rejects_collapse_to_one_first_rule(self):
        config = _config("172.19.0.1/30", "192.0.2.53")
        unrelated = {"domain_suffix": ["unrelated.example"], "outbound": "direct"}
        config["route"]["rules"] = [
            {"ip_is_private": True, "outbound": "direct"},
            {"ip_version": "6", "action": "reject"},
            unrelated,
            {"ip_version": 6, "action": "reject"},
        ]
        self.policy.ensure_ipv4_only(config)
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"ip_version": 6, "action": "reject"})
        self.assertEqual(
            [
                rule
                for rule in rules
                if str(rule.get("ip_version")) == "6"
                and rule.get("action") == "reject"
            ],
            [{"ip_version": 6, "action": "reject"}],
        )
        self.assertEqual(
            rules[1:],
            [
                {"ip_is_private": True, "outbound": "direct"},
                unrelated,
            ],
        )

    def test_normalize_orders_policy_and_preserves_unrelated_rules(self):
        unrelated = {"domain_suffix": ["corp.example"], "outbound": "direct"}
        config = {
            "dns": {"servers": [], "strategy": "prefer_ipv4"},
            "inbounds": [{"type": "tun", "address": "172.19.0.1/30"}],
            "route": {
                "rules": [
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"ip_version": 6, "action": "reject"},
                    {"action": "sniff"},
                    unrelated,
                    {"ip_is_private": True, "outbound": "direct"},
                    {"action": "reject", "network": "udp", "port": 443},
                ]
            },
        }
        self.policy.normalize(config)
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"ip_version": 6, "action": "reject"})
        self.assertEqual(rules[1], {"ip_is_private": True, "outbound": "direct"})
        self.assertTrue(self.policy.is_udp443_reject(rules[2]))
        self.assertEqual(rules[3], {"protocol": "dns", "action": "hijack-dns"})
        self.assertEqual(rules[4], {"action": "sniff"})
        self.assertEqual(rules[5], unrelated)
        self.assertEqual(len(rules), 6)
        self.assertEqual(
            sum(1 for rule in rules if self.policy.is_udp443_reject(rule)),
            1,
        )
        self.assertEqual(
            [
                rule
                for rule in rules
                if str(rule.get("ip_version")) == "6"
                and rule.get("action") == "reject"
            ],
            [{"ip_version": 6, "action": "reject"}],
        )

    def test_custom_rules_keep_order_and_scoped_reject(self):
        custom = {"domain_suffix": ["corp.example"], "outbound": "direct"}
        dns = {"protocol": "dns", "action": "hijack-dns"}
        scoped = {"action": "reject", "network": "udp", "port": 443, "domain": ["example.org"]}
        config = _config("172.19.0.1/30", "192.0.2.53")
        config["route"]["rules"] += [custom, dns, scoped]
        self.policy.normalize(config)
        self.policy.normalize(config)
        rules = config["route"]["rules"]
        self.assertEqual(rules[-3:], [custom, dns, scoped])
        self.assertEqual(sum(self.policy.is_udp443_reject(r) for r in rules), 1)

    def test_ipv4_private_direct_stays_before_udp_reject(self):
        private = {"ip_is_private": True, "ip_version": 4, "outbound": "direct"}
        config = _config("172.19.0.1/30", "192.0.2.53")
        config["route"]["rules"] = [private, {"action": "sniff"}]
        self.policy.normalize(config)
        self.assertEqual(config["route"]["rules"][1], private)
        self.assertTrue(self.policy.is_udp443_reject(config["route"]["rules"][2]))


if __name__ == "__main__":
    unittest.main()
