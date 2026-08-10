import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.email_sender import _build_email_body
from ct_watcher.state import state


class TestBuildEmailBody:
    def test_keyword_email_uses_only_matched_keywords(self):
        with patch.object(
            state,
            "email_template",
            "{IDENTIFIER}\n\nIOCs:\n{IOCS_LIST}",
        ):
            body = _build_email_body(
                all_domains=["calcentraltiw.evil.example.com"],
                non_cdn_ips=None,
                api_ids=[],
                keyword="berkeley",
                matched_keywords=["calcentraltiw"],
            )

        assert "Matched keyword(s): calcentraltiw" in body
        assert "berkeley" not in body
        assert "calcentraltiw[.]evil[.]example[.]com" in body

    def test_duo_email_remains_unchanged(self):
        with patch.object(state, "email_template", "{IDENTIFIER}"):
            body = _build_email_body(
                all_domains=["api-deadbeef.evil.example.com"],
                non_cdn_ips=None,
                api_ids=["deadbeef"],
            )

        assert "Duo API hostname:" in body
        assert "https://api-deadbeef.duosecurity.com" in body
