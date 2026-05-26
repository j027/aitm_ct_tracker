"""Tests for dns_resolver module with real DNS resolution."""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.dns_resolver import resolve_a, resolve_ns


class TestResolveA:
    """Tests for resolve_a with real DNS queries."""

    def test_google_com_has_ipv4(self):
        ips = resolve_a("google.com")
        assert len(ips) > 0, "google.com should have at least one A record"
        for ip in ips:
            assert re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip), f"Invalid IPv4: {ip}"

    def test_cloudflare_com_has_ipv4(self):
        ips = resolve_a("cloudflare.com")
        assert len(ips) > 0, "cloudflare.com should have at least one A record"
        for ip in ips:
            assert re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip), f"Invalid IPv4: {ip}"

    def test_nonexistent_domain_returns_empty(self):
        ips = resolve_a("nonexistent-domain-xyz123abc.invalid")
        assert ips == [], "Nonexistent domain should return empty list"

    def test_domain_with_no_a_records_returns_empty(self):
        ips = resolve_a("example.test")
        assert ips == [], "Domain with no A records should return empty list"


class TestResolveNS:
    """Tests for resolve_ns with real DNS queries."""

    def test_google_com_has_nameservers(self):
        ns_list = resolve_ns("google.com")
        assert len(ns_list) > 0, "google.com should have nameservers"
        assert any("google" in ns.lower() or "ns" in ns.lower() for ns in ns_list), (
            f"Expected Google nameservers, got: {ns_list}"
        )

    def test_cloudflare_com_has_nameservers(self):
        ns_list = resolve_ns("cloudflare.com")
        assert len(ns_list) > 0, "cloudflare.com should have nameservers"
        assert any("cloudflare" in ns.lower() for ns in ns_list), (
            f"Expected Cloudflare nameservers, got: {ns_list}"
        )

    def test_nonexistent_domain_returns_empty(self):
        ns_list = resolve_ns("nonexistent-domain-xyz123abc.invalid")
        assert ns_list == [], "Nonexistent domain should return empty list"


class TestDoHMode:
    """Tests for DoH mode when DOH_SERVER is set."""

    def test_doh_resolves_google_com(self):
        """Test that DoH resolver works when DOH_SERVER is set."""
        from ct_watcher import dns_resolver

        original_doh = os.environ.get("DOH_SERVER")
        old_doh_enabled = dns_resolver._doh_enabled
        try:
            os.environ["DOH_SERVER"] = "https://cloudflare-dns.com/dns-query"
            dns_resolver._doh_enabled = None

            ips = resolve_a("google.com")
            assert len(ips) > 0, "DoH should resolve google.com successfully"
            for ip in ips:
                assert re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip), f"Invalid IPv4: {ip}"
        finally:
            if original_doh is None:
                os.environ.pop("DOH_SERVER", None)
            else:
                os.environ["DOH_SERVER"] = original_doh
            dns_resolver._doh_enabled = old_doh_enabled
