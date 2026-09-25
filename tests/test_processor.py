import json
import os
import sys
import threading
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher import state
from ct_watcher.config import MAX_CERT_AGE_SECONDS
from ct_watcher.email_sender import EmailSendStatus
from ct_watcher.processor import (
    _build_certkit_url,
    _certificate_id,
    _claim_certificate,
    _finalize_alert,
    _handle_known_attacker,
    _handle_pattern_match,
    process_message,
)

_EMPTY_SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
_SERIAL = "0526D195A45A0C210D819B7E85435FF35CC6"
_VALID_SHA256 = "A6D87DF509F3A01C1329873093ACAD5F4930BCB582B0CCD70790A1195E284BCA"
_COLON_SEP = ":"  # for constructing colon-separated hex strings in tests


class TestBuildCertkitUrl:
    def test_normal_sha_with_colons(self):
        colon_sha = _COLON_SEP.join(_VALID_SHA256[i : i + 2] for i in range(0, 64, 2))
        url = _build_certkit_url(colon_sha, _SERIAL)
        expected = f"https://www.certkit.io/tools/ct-logs/certificate?sha256={_VALID_SHA256}"
        assert url == expected

    def test_normal_sha_without_colons(self):
        url = _build_certkit_url(_VALID_SHA256, _SERIAL)
        assert url == (f"https://www.certkit.io/tools/ct-logs/certificate?sha256={_VALID_SHA256}")

    def test_bogus_sha_falls_back_to_serial(self):
        url = _build_certkit_url(
            ":" + _EMPTY_SHA256[:2] + ":".join(_EMPTY_SHA256[i : i + 2] for i in range(2, 64, 2)),
            _SERIAL,
        )
        assert url == (f"https://www.certkit.io/tools/ct-logs/certificate?serial={_SERIAL}")

    def test_bogus_sha_without_serial_returns_none(self):
        url = _build_certkit_url(_EMPTY_SHA256, None)
        assert url is None

    def test_bogus_sha_case_insensitive(self):
        lower = _EMPTY_SHA256.lower()
        url = _build_certkit_url(
            ":".join(lower[i : i + 2] for i in range(0, 64, 2)),
            _SERIAL,
        )
        assert url == (f"https://www.certkit.io/tools/ct-logs/certificate?serial={_SERIAL}")

    def test_no_sha_uses_serial(self):
        url = _build_certkit_url(None, _SERIAL)
        assert url == (f"https://www.certkit.io/tools/ct-logs/certificate?serial={_SERIAL}")

    def test_no_sha_no_serial_returns_none(self):
        url = _build_certkit_url(None, None)
        assert url is None

    def test_empty_string_sha_uses_serial(self):
        url = _build_certkit_url("", _SERIAL)
        assert url == (f"https://www.certkit.io/tools/ct-logs/certificate?serial={_SERIAL}")

    def test_sha256_preferred_over_serial(self):
        url = _build_certkit_url(_VALID_SHA256, _SERIAL)
        assert url is not None
        assert "sha256=" in url
        assert "serial=" not in url


class TestFinalizeAlert:
    def test_keyword_matches_reach_email_and_alert(self):
        original_targets = state.state.keyword_targets
        state.state.keyword_targets = {
            "berkeley": {
                "type": "keyword",
                "name": "University of California, Berkeley",
                "email": "security@berkeley.edu",
                "keywords": ["calcentraltiw", "notmatched"],
            }
        }
        try:
            with patch("ct_watcher.processor.send_automated_target_email") as send_email:
                with patch("ct_watcher.processor._dispatch_alert") as dispatch_alert:
                    send_email.return_value = EmailSendStatus("skipped", "test")
                    _finalize_alert(
                        domain="calcentraltiw.evil.example.com",
                        all_domains=["calcentraltiw.evil.example.com"],
                        not_before=None,
                        is_known_attacker=False,
                        registrar=None,
                        is_cloudflare=False,
                        nameservers_list=None,
                        all_ips=[],
                        non_cdn_ips=[],
                        confirmed_attacker_ip_matches=[],
                        reg_date=None,
                        api_ids=[],
                        api_id=None,
                        certkit_url=None,
                        sha256=None,
                        serial_number=None,
                        keyword="berkeley",
                        keyword_match_domains=["calcentraltiw.evil.example.com"],
                        matched_keywords=["calcentraltiw"],
                    )

            assert send_email.call_args.kwargs["matched_keywords"] == ["calcentraltiw"]
            alert = dispatch_alert.call_args.args[0]
            assert alert.matched_keywords == ["calcentraltiw"]
        finally:
            state.state.keyword_targets = original_targets


class TestCertificateId:
    def test_normalizes_serial_and_includes_issuer(self):
        leaf_cert = {
            "issuer": {"aggregated": "/C=US/O=Let's Encrypt/CN=YR1"},
            "serial_number": "05:ca:92:62:0f:1a:f0:3f:10:de:b7:32:87:15:6d:78:a6:0c",
        }
        assert _certificate_id(leaf_cert) == (
            "/C=US/O=Let's Encrypt/CN=YR1|05CA92620F1AF03F10DEB73287156D78A60C"
        )

    def test_precert_and_final_share_identity(self):
        issuer = {"aggregated": "/C=US/O=Let's Encrypt/CN=YR1"}
        serial = "0683C1427540AE396C468108F2285219DF6F"
        precert = {
            "issuer": issuer,
            "serial_number": serial,
            "sha256": (
                "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:"
                "E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
            ),
        }
        final = {
            "issuer": issuer,
            "serial_number": serial,
            "sha256": (
                "3E:89:F3:5B:F6:92:24:3E:79:F1:79:C6:12:D9:1E:C1:69:DD:13:40:"
                "C6:05:4A:6F:7B:2D:A3:E8:75:39:C1:75"
            ),
        }
        assert _certificate_id(precert) == _certificate_id(final)

    def test_missing_serial_returns_none(self):
        assert _certificate_id({"issuer": {"aggregated": "/C=US/O=Test"}}) is None

    def test_empty_serial_returns_none(self):
        assert _certificate_id({"serial_number": "  ", "issuer": {"aggregated": "x"}}) is None


class TestClaimCertificate:
    def test_first_claim_wins(self):
        state.state.alerted_certificates.clear()
        assert _claim_certificate("issuer|AAAA") is True
        assert _claim_certificate("issuer|AAAA") is False

    def test_concurrent_claims_only_one_wins(self):
        state.state.alerted_certificates.clear()
        results = []
        results_lock = threading.Lock()

        def worker():
            claimed = _claim_certificate("issuer|CONCURRENT")
            with results_lock:
                results.append(claimed)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1


class TestHandlerCertificateDedup:
    domain = "host1.example-university.test"
    all_domains = [
        "host1.example-university.test",
        "api-1234abcd.example-university.test",
        "auth.example-university.test",
        "assets.example-university.test",
    ]

    def _run_known_attacker(self, cert_id):
        with (
            patch("ct_watcher.processor.get_nameservers", return_value=(False, [])),
            patch("ct_watcher.processor.get_domain_info", return_value=(None, None)),
            patch("ct_watcher.processor.get_attacker_ips_for_domain", return_value=([], [])),
            patch("ct_watcher.processor._finalize_alert") as finalize,
        ):
            result = _handle_known_attacker(
                domain=self.domain,
                all_domains=self.all_domains,
                cert_id=cert_id,
                not_before=None,
            )
        return result, finalize

    def test_same_certificate_alerts_once(self):
        state.state.alerted_certificates.clear()
        first, first_finalize = self._run_known_attacker("issuer|AAAA")
        second, second_finalize = self._run_known_attacker("issuer|AAAA")

        assert first is True
        assert first_finalize.call_count == 1
        assert second is False
        assert second_finalize.call_count == 0

    def test_different_certificates_with_shared_san_both_alert(self):
        state.state.alerted_certificates.clear()
        first, first_finalize = self._run_known_attacker("issuer|AAAA")
        second, second_finalize = self._run_known_attacker("issuer|BBBB")

        assert first is True
        assert second is True
        assert first_finalize.call_count == 1
        assert second_finalize.call_count == 1

    def test_low_confidence_pattern_does_not_claim_certificate(self):
        state.state.alerted_certificates.clear()
        with (
            patch("ct_watcher.processor.get_nameservers", return_value=(False, [])),
            patch("ct_watcher.processor.get_domain_info", return_value=(None, None)),
            patch("ct_watcher.processor.resolve_and_classify", return_value=([], [])),
            patch("ct_watcher.processor._finalize_alert") as finalize,
        ):
            result = _handle_pattern_match(
                domain="api-abcde.evil.example.com",
                all_domains=["api-abcde.evil.example.com", "other.evil.example.com"],
                cert_id="issuer|CCCC",
                not_before=None,
            )

        assert result is False
        assert finalize.call_count == 0
        assert "issuer|CCCC" not in state.state.alerted_certificates

    def test_high_confidence_pattern_claims_certificate(self):
        state.state.alerted_certificates.clear()
        with (
            patch(
                "ct_watcher.processor.get_nameservers",
                return_value=(True, ["ns.cloudflare.com"]),
            ),
            patch("ct_watcher.processor.get_domain_info", return_value=(None, None)),
            patch("ct_watcher.processor.resolve_and_classify", return_value=([], [])),
            patch("ct_watcher.processor.track_resolved_ips"),
            patch("ct_watcher.processor._finalize_alert") as finalize,
        ):
            first = _handle_pattern_match(
                domain="api-1234abcd.evil.example.com",
                all_domains=["api-1234abcd.evil.example.com", "other.evil.example.com"],
                cert_id="issuer|DDDD",
                not_before=None,
            )
            second = _handle_pattern_match(
                domain="api-1234abcd.evil.example.com",
                all_domains=["api-1234abcd.evil.example.com", "other.evil.example.com"],
                cert_id="issuer|DDDD",
                not_before=None,
            )

        assert first is True
        assert second is False
        assert finalize.call_count == 1


class TestCertificateAgeGuard:
    NOW = 1_700_000_000.0

    def _message(self, not_before, serial="ABCDEF"):
        leaf_cert = {
            "all_domains": ["evil-known.test"],
            "issuer": {"aggregated": "/C=US/O=Test/CN=Test"},
            "serial_number": serial,
        }
        if not_before is not None:
            leaf_cert["not_before"] = not_before
        return json.dumps({"message_type": "certificate_update", "data": {"leaf_cert": leaf_cert}})

    def _run(self, message):
        state.state.alerted_certificates.clear()
        state.state.cert_count = 0
        with (
            patch("ct_watcher.processor.time.time", return_value=self.NOW),
            patch("ct_watcher.processor.is_known_attacker_domain", return_value=True),
            patch("ct_watcher.processor._handle_known_attacker") as handler,
            patch("ct_watcher.processor.log") as log,
        ):
            process_message(message)
        return handler, log

    def test_fresh_certificate_alerts_and_counts(self):
        handler, _ = self._run(self._message(self.NOW - 300, serial="FRESH"))
        assert handler.call_count == 1
        assert state.state.cert_count == 1

    def test_stale_certificate_skipped_without_counting(self):
        handler, _ = self._run(self._message(self.NOW - MAX_CERT_AGE_SECONDS - 1, serial="STALE"))
        assert handler.call_count == 0
        assert state.state.cert_count == 0

    def test_boundary_certificate_alerts(self):
        handler, _ = self._run(self._message(self.NOW - MAX_CERT_AGE_SECONDS, serial="BOUNDARY"))
        assert handler.call_count == 1
        assert state.state.cert_count == 1

    def test_missing_not_before_skipped_with_log(self):
        handler, log = self._run(self._message(None, serial="MISSING"))
        assert handler.call_count == 0
        assert state.state.cert_count == 0
        assert any("invalid not_before" in str(call.args[0]) for call in log.call_args_list)

    def test_malformed_not_before_skipped_with_log(self):
        handler, log = self._run(self._message("not-a-timestamp", serial="MALFORMED"))
        assert handler.call_count == 0
        assert state.state.cert_count == 0
        assert any("invalid not_before" in str(call.args[0]) for call in log.call_args_list)
