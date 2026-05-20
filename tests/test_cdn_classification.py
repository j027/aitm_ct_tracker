import pytest
import sys
import os
import ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.config import CDN_NETWORKS

# Populate CDN_NETWORKS for tests since it's no longer hardcoded
_TEST_CDN_RANGES = [
    # Cloudflare
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "173.245.48.0/20",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "188.114.96.0/20", "162.158.0.0/15",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Akamai
    "23.0.0.0/12", "104.64.0.0/10",
    # CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15",
    "54.192.0.0/16", "99.84.0.0/16", "205.251.192.0/19",
]
for cidr in _TEST_CDN_RANGES:
    try:
        CDN_NETWORKS.append(ipaddress.ip_network(cidr))
    except ValueError:
        pass

from ct_watcher.ip_tracking import is_cdn_ip


class TestCdnClassification:
    """Tests for is_cdn_ip function."""

    @pytest.mark.parametrize("ip", [
        "104.16.0.1",
        "104.24.0.1",
        "172.64.0.1",
        "173.245.48.1",
        "141.101.64.1",
        "108.162.192.1",
        "190.93.240.1",
        "188.114.96.1",
        "162.158.0.1",
    ])
    def test_cloudflare_ips(self, ip):
        assert is_cdn_ip(ip), f"Should be CDN (Cloudflare): {ip}"

    @pytest.mark.parametrize("ip", [
        "151.101.1.1",
        "151.101.65.1",
        "151.101.129.1",
        "199.232.0.1",
    ])
    def test_fastly_ips(self, ip):
        assert is_cdn_ip(ip), f"Should be CDN (Fastly): {ip}"

    @pytest.mark.parametrize("ip", [
        "23.0.0.1",
        "104.64.0.1",
    ])
    def test_akamai_ips(self, ip):
        assert is_cdn_ip(ip), f"Should be CDN (Akamai): {ip}"

    @pytest.mark.parametrize("ip", [
        "13.32.0.1",
        "13.35.0.1",
        "52.84.0.1",
        "54.192.0.1",
        "99.84.0.1",
        "205.251.192.1",
    ])
    def test_cloudfront_ips(self, ip):
        assert is_cdn_ip(ip), f"Should be CDN (CloudFront): {ip}"

    @pytest.mark.parametrize("ip", [
        "208.109.244.86",
        "160.153.176.169",
        "104.207.70.137",
        "8.8.8.8",
        "1.0.0.2",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "203.0.113.1",
    ])
    def test_non_cdn_ips(self, ip):
        assert not is_cdn_ip(ip), f"Should NOT be CDN: {ip}"

    def test_invalid_ip(self):
        assert not is_cdn_ip("not-an-ip")
        assert not is_cdn_ip("")
        assert not is_cdn_ip("999.999.999.999")
