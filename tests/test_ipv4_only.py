#!/usr/bin/env python3
"""Focused regression tests for the IPv4-only client normalizers."""
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
        cls.modules = [
            _load("config_policy", ROOT / "clients/linux-tray/config-policy.py"),
            _load("update_client", ROOT / "deploy/update-client.py"),
        ]

    def test_scalar_ipv6_bootstrap_is_removed(self):
        for module in self.modules:
            config = _config("172.19.0.1/30", "2606:1a40::22")
            module.ensure_ipv4_only(config)
            self.assertEqual(config["dns"]["servers"][0]["predefined"]["dns.example"], [])
            self.assertEqual(config["dns"]["strategy"], "ipv4_only")

    def test_scalar_ipv4_values_are_normalized_to_lists(self):
        for module in self.modules:
            config = _config("172.19.0.1/30", "76.76.2.22")
            module.ensure_ipv4_only(config)
            self.assertEqual(
                config["dns"]["servers"][0]["predefined"]["dns.example"],
                ["76.76.2.22"],
            )
            self.assertEqual(
                config["inbounds"][0]["address"],
                ["172.19.0.1/30"],
            )

    def test_scalar_ipv6_only_tun_is_rejected(self):
        for module in self.modules:
            config = _config("fdfe:dcba:9876::1/126", "76.76.2.22")
            with self.assertRaisesRegex(ValueError, "no IPv4 address"):
                module.ensure_ipv4_only(config)

    def test_mixed_list_is_filtered_and_idempotent(self):
        for module in self.modules:
            config = _config(
                ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                ["76.76.2.22", "2606:1a40::22"],
            )
            module.ensure_ipv4_only(config)
            module.ensure_ipv4_only(config)
            self.assertEqual(
                config["inbounds"][0]["address"],
                ["172.19.0.1/30"],
            )
            self.assertEqual(
                config["dns"]["servers"][0]["predefined"]["dns.example"],
                ["76.76.2.22"],
            )
            self.assertEqual(
                config["route"]["rules"][0],
                {"ip_version": 6, "action": "reject"},
            )


    def test_empty_tun_address_array_is_rejected(self):
        for module in self.modules:
            config = _config([], "76.76.2.22")
            with self.assertRaisesRegex(ValueError, "no IPv4 address"):
                module.ensure_ipv4_only(config)

    def test_ipv6_only_tun_array_is_rejected(self):
        for module in self.modules:
            config = _config(["fdfe:dcba:9876::1/126"], "76.76.2.22")
            with self.assertRaisesRegex(ValueError, "no IPv4 address"):
                module.ensure_ipv4_only(config)

    def test_ipv6_only_dns_array_is_emptied(self):
        for module in self.modules:
            config = _config(
                "172.19.0.1/30",
                ["2606:1a40::22", "2606:1a40::23"],
            )
            module.ensure_ipv4_only(config)
            self.assertEqual(
                config["dns"]["servers"][0]["predefined"]["dns.example"],
                [],
            )

    def test_multiple_tun_inbounds_keep_ipv4_and_reject_ipv6_only(self):
        for module in self.modules:
            config = _config("172.19.0.1/30", "76.76.2.22")
            config["inbounds"].append(
                {"type": "tun", "address": ["172.20.0.1/30", "fdfe:dcba:9876::1/126"]}
            )
            module.ensure_ipv4_only(config)
            self.assertEqual(config["inbounds"][0]["address"], ["172.19.0.1/30"])
            self.assertEqual(config["inbounds"][1]["address"], ["172.20.0.1/30"])

            rejected = _config("172.19.0.1/30", "76.76.2.22")
            rejected["inbounds"].append(
                {"type": "tun", "address": ["fdfe:dcba:9876::1/126"]}
            )
            with self.assertRaisesRegex(ValueError, "no IPv4 address"):
                module.ensure_ipv4_only(rejected)

    def test_existing_ipv6_rejects_collapse_to_one_first_rule(self):
        for module in self.modules:
            config = _config("172.19.0.1/30", "76.76.2.22")
            unrelated = {"domain_suffix": ["unrelated.example"], "outbound": "direct"}
            config["route"]["rules"] = [
                {"ip_is_private": True, "outbound": "direct"},
                {"ip_version": "6", "action": "reject"},
                unrelated,
                {"ip_version": 6, "action": "reject"},
            ]
            module.ensure_ipv4_only(config)
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
        module = self.modules[0]
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
        module.normalize(config)
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"ip_version": 6, "action": "reject"})
        self.assertEqual(rules[1], {"ip_is_private": True, "outbound": "direct"})
        self.assertTrue(module.is_udp443_reject(rules[2]))
        self.assertEqual(rules[3], {"action": "sniff"})
        self.assertEqual(rules[4], {"protocol": "dns", "action": "hijack-dns"})
        self.assertEqual(rules[5], unrelated)
        self.assertEqual(len(rules), 6)
        self.assertEqual(
            sum(1 for rule in rules if module.is_udp443_reject(rule)),
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


if __name__ == "__main__":
    unittest.main()
