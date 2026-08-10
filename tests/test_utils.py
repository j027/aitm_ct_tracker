import sys
import os
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.utils import build_identifier_text, calculate_freshness, get_base_domain


class TestCalculateFreshness:
    """Tests for calculate_freshness function."""

    def test_freshness_none(self):
        assert calculate_freshness(None) == "Unknown"
        assert calculate_freshness(None, fmt="plain") == "Unknown"

    def test_freshness_discord_format(self):
        ts = 1700000000
        result = calculate_freshness(ts, fmt="discord")
        assert result == "<t:1700000000:R>"

    def test_freshness_discord_format_float(self):
        ts = 1700000000.75
        result = calculate_freshness(ts, fmt="discord")
        assert result == "<t:1700000000:R>"

    def test_freshness_plain_seconds(self):
        ts = time.time() - 42
        result = calculate_freshness(ts, fmt="plain")
        assert result == "42 seconds"

    def test_freshness_plain_minutes(self):
        ts = time.time() - 1800
        result = calculate_freshness(ts, fmt="plain")
        assert result == "30 minutes"

    def test_freshness_plain_hours(self):
        ts = time.time() - 10800
        result = calculate_freshness(ts, fmt="plain")
        assert result == "3 hours"

    def test_freshness_plain_future_timestamp(self):
        ts = time.time() + 100
        result = calculate_freshness(ts, fmt="plain")
        assert result == "0 seconds"

    def test_freshness_default_format_is_discord(self):
        ts = 1700000000
        result = calculate_freshness(ts)
        assert result == "<t:1700000000:R>"


class TestBaseDomain:
    def test_simple_tld(self):
        assert get_base_domain("api-abc.evil.com") == "evil.com"
        assert get_base_domain("evil.com") == "evil.com"

    def test_multi_part_tld(self):
        assert get_base_domain("phish.co.uk") == "phish.co.uk"
        assert get_base_domain("test.com.au") == "test.com.au"

    def test_shared_hosting_platform(self):
        assert get_base_domain("myapp.azurewebsites.net") == "azurewebsites.net"
        assert get_base_domain("www.myapp.azurewebsites.net") == "azurewebsites.net"


class TestBuildIdentifierText:
    def test_single_duo_id(self):
        result = build_identifier_text(api_ids=["deadbeef"])
        assert "https://api-deadbeef.duosecurity.com" in result
        assert "Duo API hostname:" in result
        assert result.count("https://api-") == 1

    def test_multiple_duo_ids(self):
        result = build_identifier_text(api_ids=["deadbeef", "cafebabe"])
        assert "https://api-deadbeef.duosecurity.com" in result
        assert "https://api-cafebabe.duosecurity.com" in result
        assert result.count("https://api-") == 2

    def test_keyword_match(self):
        result = build_identifier_text(
            keyword="berkeley",
            matched_keywords=["calcentraltiw"],
        )
        assert "Matched keyword(s): calcentraltiw" in result
        assert "berkeley" not in result

    def test_keyword_overrides_api_ids(self):
        result = build_identifier_text(
            api_ids=["deadbeef"],
            keyword="berkeley",
            matched_keywords=["calcentraltiw"],
        )
        assert "Matched keyword(s): calcentraltiw" in result
        assert "duosecurity.com" not in result

    def test_multiple_matched_keywords(self):
        result = build_identifier_text(
            keyword="morgan",
            matched_keywords=["morgan", "mailladfmro"],
        )
        assert "Matched keyword(s): morgan, mailladfmro" in result

    def test_keyword_requires_matched_keywords(self):
        with pytest.raises(ValueError, match="matched_keywords is required"):
            build_identifier_text(keyword="legacy-key")

    def test_keyword_attribution_note(self):
        result = build_identifier_text(
            keyword="berkeley",
            matched_keywords=["calcentraltiw"],
        )
        assert "keyword match" in result
        assert "more likely to result in false positives" in result

    def test_empty_returns_empty(self):
        result = build_identifier_text()
        assert result == ""

    def test_empty_api_ids_returns_empty(self):
        result = build_identifier_text(api_ids=[])
        assert result == ""
