import sys
import os
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.apprise import build_apprise_alert
from ct_watcher.models import AlertInfo


SAMPLE_TARGET = {"name": "Test University", "email": "security@test.edu"}
SAMPLE_TARGET_MAPPING = {"529aed63": SAMPLE_TARGET}


def _make_alert(**overrides):
    """Create an AlertInfo with sensible defaults for testing."""
    defaults = dict(
        domain="api-529aed63.evil.com",
        all_domains=["api-529aed63.evil.com"],
        not_before=None,
        is_known_attacker=False,
        registrar=None,
        is_cloudflare=False,
        nameservers_list=None,
        all_ips=None,
        non_cdn_ips=None,
        confirmed_attacker_ip_matches=None,
        reg_date=None,
        email_status_details="",
        email_status_state="pending",
        target_info=None,
        api_id=None,
        certkit_url=None,
        sha256=None,
        serial_number=None,
    )
    defaults.update(overrides)
    return AlertInfo(**defaults)


class TestAppriseAlertTitle:
    """Tests for alert title rendering."""

    def test_known_attacker_title(self):
        result = build_apprise_alert(_make_alert(
            domain="attacker.com",
            all_domains=["attacker.com"],
            is_known_attacker=True,
        ))
        assert "KNOWN ATTACKER DOMAIN DETECTED" in result

    def test_pattern_match_title(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            is_known_attacker=False,
        ))
        assert "Potential Target Match" in result


class TestAppriseTargetResolution:
    """Tests for target organization resolution scenarios."""

    def test_target_info_passed_directly(self):
        """Known attacker domain with no api-ID, target resolved from scanning all_domains."""
        result = build_apprise_alert(_make_alert(
            domain="attacker.com",
            all_domains=["attacker.com", "api-529aed63.evil.com"],
            is_known_attacker=True,
            target_info=SAMPLE_TARGET,
        ))
        assert "Test University" in result
        assert "security@test.edu" in result

    @patch("ct_watcher.apprise.state")
    def test_target_info_from_state_lookup(self, mock_state):
        """api-ID in matched domain, target found in state.target_mapping."""
        mock_state.target_mapping = SAMPLE_TARGET_MAPPING
        mock_state.email_template = ""
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
        ))
        assert "Test University" in result
        assert "security@test.edu" in result

    @patch("ct_watcher.apprise.state")
    def test_unknown_target_hex_id(self, mock_state):
        """api-ID in matched domain but not in target_mapping."""
        mock_state.target_mapping = {}
        mock_state.email_template = ""
        result = build_apprise_alert(_make_alert(
            domain="api-abcdef.evil.com",
            all_domains=["api-abcdef.evil.com"],
        ))
        assert "Hex ID:" in result
        assert "abcdef" in result
        assert "Unknown Target" in result

    def test_no_api_id_no_target(self):
        """Bare domain with no api-ID and no target_info passed."""
        result = build_apprise_alert(_make_alert(
            domain="attacker.com",
            all_domains=["attacker.com"],
        ))
        assert "Target Organization:" not in result
        assert "Hex ID:" not in result


class TestAppriseAlertFields:
    """Tests for individual field rendering."""

    def test_matched_domain_defanged(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
        ))
        assert "api-529aed63[.]evil[.]com" in result

    def test_email_status_included(self):
        with patch("ct_watcher.apprise.EMAIL_ENABLED", True):
            result = build_apprise_alert(_make_alert(
                domain="api-529aed63.evil.com",
                all_domains=["api-529aed63.evil.com"],
                email_status_details="Email sent successfully",
            ))
        assert "Email Status:" in result
        assert "Email sent successfully" in result

    def test_email_status_omitted_when_disabled(self):
        with patch("ct_watcher.apprise.EMAIL_ENABLED", False):
            result = build_apprise_alert(_make_alert(
                domain="api-529aed63.evil.com",
                all_domains=["api-529aed63.evil.com"],
                email_status_details="Email sent successfully",
            ))
        assert "Email Status:" not in result

    def test_registrar_shown(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar="Namecheap",
        ))
        assert "Namecheap" in result

    def test_registrar_unknown(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            registrar=None,
        ))
        assert "Unknown" in result

    def test_confirmed_attacker_ip_match(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            all_ips=["1.2.3.4", "5.6.7.8"],
            confirmed_attacker_ip_matches=["1.2.3.4"],
        ))
        assert "Confirmed Attacker IP Match:" in result
        assert "1.2.3.4" in result

    def test_ip_addresses_with_cdn_tags(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            all_ips=["1.2.3.4", "5.6.7.8"],
            non_cdn_ips=["1.2.3.4"],
        ))
        assert "1.2.3.4 (non-cdn)" in result
        assert "5.6.7.8 (cdn)" in result

    def test_nameserver_info(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            nameservers_list=["ns1.cloudflare.com", "ns2.cloudflare.com"],
            is_cloudflare=True,
        ))
        assert "Cloudflare Nameservers:" in result
        assert "Yes" in result
        assert "ns1.cloudflare.com" in result

    def test_certkit_url_in_output(self):
        url = "https://www.certkit.io/tools/ct-logs/certificate?sha256=abcd1234"
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            certkit_url=url,
        ))
        assert "**CertKit:**" in result
        assert url in result

    def test_certkit_url_absent_when_none(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            certkit_url=None,
        ))
        assert "CertKit:" not in result


class TestAppriseAllDomainsBlock:
    """Tests for all domains rendering."""

    def test_all_domains_defanged(self):
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com", "evil.com"],
        ))
        assert "api-529aed63[.]evil[.]com" in result
        assert "evil[.]com" in result

    def test_domains_capped_at_50(self):
        domains = [f"api-529aed63.sub{i}.evil.com" for i in range(60)]
        result = build_apprise_alert(_make_alert(
            domain=domains[0],
            all_domains=domains,
        ))
        assert "... and 10 more" in result

    def test_freshness_in_output(self):
        ts = time.time() - 300
        result = build_apprise_alert(_make_alert(
            domain="api-529aed63.evil.com",
            all_domains=["api-529aed63.evil.com"],
            not_before=ts,
        ))
        assert "Certificate Freshness:" in result
        assert "5 minutes" in result
