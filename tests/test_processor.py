import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher import state
from ct_watcher.email_sender import EmailSendStatus
from ct_watcher.processor import _build_certkit_url, _finalize_alert

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
