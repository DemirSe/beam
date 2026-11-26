package com.beam.android.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsValidatorTest {

    @Test
    fun `valid DoH URLs normalize scheme and pass`() {
        assertEquals(
            "https://1.1.1.1/dns-query",
            SettingsValidator.normalizeAndValidateDohUrl("https://1.1.1.1/dns-query"),
        )
        assertEquals(
            "https://dns.nextdns.io/abc123",
            SettingsValidator.normalizeAndValidateDohUrl("  HTTPS://dns.nextdns.io/abc123  "),
        )
        assertEquals(
            "https://[2606:4700:4700::1111]:443/dns-query",
            SettingsValidator.normalizeAndValidateDohUrl("https://[2606:4700:4700::1111]:443/dns-query"),
        )
        assertEquals(
            "https://dns.quad9.net",
            SettingsValidator.normalizeAndValidateDohUrl("https://dns.quad9.net"),
        )
    }

    @Test
    fun `invalid DoH URLs rejected to match Rust DnsUpstream parse`() {
        assertNull(SettingsValidator.normalizeAndValidateDohUrl(""))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("http://1.1.1.1/dns-query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https://user@dns.example.com/dns-query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https://dns.example.com/dns query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https://dns.example.com:0/dns-query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https://dns.example.com:70000/dns-query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https:///dns-query"))
        assertNull(SettingsValidator.normalizeAndValidateDohUrl("https://dns.example.com/" + "a".repeat(520)))
    }

    @Test
    fun `isIpLiteral distinguishes literal IPs from hostnames`() {
        assertTrue(SettingsValidator.isIpLiteral("1.1.1.1"))
        assertTrue(SettingsValidator.isIpLiteral("203.0.113.10"))
        assertTrue(SettingsValidator.isIpLiteral("2001:db8::1"))
        assertTrue(SettingsValidator.isIpLiteral("[2001:db8::1]"))
        assertFalse(SettingsValidator.isIpLiteral("vpn.example.com"))
        assertFalse(SettingsValidator.isIpLiteral("999.1.1.1"))
        assertFalse(SettingsValidator.isIpLiteral(""))
    }
}
