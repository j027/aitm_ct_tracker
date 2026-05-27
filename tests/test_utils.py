import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.utils import calculate_freshness


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
