import json
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.cdn_fetcher import (
    _fetch_cloudflare,
    _fetch_fastly,
    fetch_all,
    save_cache,
    load_cache,
    refresh_cdn_cache,
    load_cdn_networks,
)


class TestFetchCloudflare:
    """Tests for Cloudflare CDN range fetching."""

    def test_fetch_cloudflare_parses_cidrs(self):
        mock_resp = MagicMock()
        mock_resp.text = "173.245.48.0/20\n103.21.244.0/22\n104.16.0.0/13\n"
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_cloudflare()

        assert cidrs == ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"]

    def test_fetch_cloudflare_skips_invalid(self):
        mock_resp = MagicMock()
        mock_resp.text = "173.245.48.0/20\nnot-a-cidr\n104.16.0.0/13\n"
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_cloudflare()

        assert cidrs == ["173.245.48.0/20", "104.16.0.0/13"]

    def test_fetch_cloudflare_handles_empty_lines(self):
        mock_resp = MagicMock()
        mock_resp.text = "\n173.245.48.0/20\n\n104.16.0.0/13\n"
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_cloudflare()

        assert cidrs == ["173.245.48.0/20", "104.16.0.0/13"]

    def test_fetch_cloudflare_raises_on_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 500")

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            with pytest.raises(Exception):
                _fetch_cloudflare()


class TestFetchFastly:
    """Tests for Fastly CDN range fetching."""

    def test_fetch_fastly_parses_addresses(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "addresses": ["23.235.32.0/20", "151.101.0.0/16", "199.232.0.0/16"]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_fastly()

        assert cidrs == ["23.235.32.0/20", "151.101.0.0/16", "199.232.0.0/16"]

    def test_fetch_fastly_skips_invalid(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "addresses": ["23.235.32.0/20", "not-a-cidr", "151.101.0.0/16"]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_fastly()

        assert cidrs == ["23.235.32.0/20", "151.101.0.0/16"]

    def test_fetch_fastly_handles_empty_addresses(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"addresses": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("ct_watcher.cdn_fetcher.requests.get", return_value=mock_resp):
            cidrs = _fetch_fastly()

        assert cidrs == []


class TestFetchAll:
    """Tests for combined fetch_all function."""

    def test_fetch_all_returns_both_providers(self):
        with patch("ct_watcher.cdn_fetcher._fetch_cloudflare", return_value=["1.1.1.0/24"]), \
             patch("ct_watcher.cdn_fetcher._fetch_fastly", return_value=["2.2.2.0/24"]):
            result = fetch_all()

        assert result == {"cloudflare": ["1.1.1.0/24"], "fastly": ["2.2.2.0/24"]}

    def test_fetch_all_handles_partial_failure(self):
        with patch("ct_watcher.cdn_fetcher._fetch_cloudflare", return_value=["1.1.1.0/24"]), \
             patch("ct_watcher.cdn_fetcher._fetch_fastly", side_effect=Exception("fail")):
            result = fetch_all()

        assert result == {"cloudflare": ["1.1.1.0/24"]}

    def test_fetch_all_handles_total_failure(self):
        with patch("ct_watcher.cdn_fetcher._fetch_cloudflare", side_effect=Exception("fail")), \
             patch("ct_watcher.cdn_fetcher._fetch_fastly", side_effect=Exception("fail")):
            result = fetch_all()

        assert result == {}


class TestCache:
    """Tests for cache save/load functionality."""

    def test_save_and_load_cache(self, tmp_path):
        cache_file = str(tmp_path / "test_cache.json")
        provider_ranges = {
            "cloudflare": ["1.1.1.0/24"],
            "fastly": ["2.2.2.0/24"],
        }

        save_cache(provider_ranges, cache_file)
        loaded = load_cache(cache_file)

        assert loaded == provider_ranges

    def test_load_cache_returns_none_if_missing(self):
        assert load_cache("/nonexistent/path/cache.json") is None

    def test_load_cache_returns_none_if_expired(self, tmp_path):
        cache_file = str(tmp_path / "expired_cache.json")
        provider_ranges = {"cloudflare": ["1.1.1.0/24"]}

        save_cache(provider_ranges, cache_file)

        # Manually set the timestamp to 25 hours ago
        with open(cache_file, "r") as f:
            cache = json.load(f)

        from datetime import datetime, timezone, timedelta
        cache["updated_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        with open(cache_file, "w") as f:
            json.dump(cache, f)

        assert load_cache(cache_file) is None


class TestRefreshCdnCache:
    """Tests for refresh_cdn_cache function."""

    def test_refresh_fetches_and_saves(self, tmp_path):
        cache_file = str(tmp_path / "test_cache.json")

        with patch("ct_watcher.cdn_fetcher.fetch_all", return_value={
            "cloudflare": ["1.1.1.0/24"],
            "fastly": ["2.2.2.0/24"],
        }):
            result = refresh_cdn_cache(cache_file)

        assert result == {"cloudflare": ["1.1.1.0/24"], "fastly": ["2.2.2.0/24"]}
        assert os.path.exists(cache_file)

    def test_refresh_falls_back_to_cache(self, tmp_path):
        cache_file = str(tmp_path / "test_cache.json")
        provider_ranges = {"cloudflare": ["1.1.1.0/24"]}
        save_cache(provider_ranges, cache_file)

        with patch("ct_watcher.cdn_fetcher.fetch_all", return_value={}):
            result = refresh_cdn_cache(cache_file)

        assert result == provider_ranges

    def test_refresh_returns_empty_on_total_failure(self, tmp_path):
        cache_file = str(tmp_path / "nonexistent_cache.json")

        with patch("ct_watcher.cdn_fetcher.fetch_all", return_value={}):
            result = refresh_cdn_cache(cache_file)

        assert result == {}


class TestLoadCdnNetworks:
    """Tests for load_cdn_networks function."""

    def test_load_cdn_networks_returns_networks(self, tmp_path):
        cache_file = str(tmp_path / "test_cache.json")
        provider_ranges = {
            "cloudflare": ["104.16.0.0/13"],
            "fastly": ["151.101.0.0/16"],
        }
        save_cache(provider_ranges, cache_file)

        with patch("ct_watcher.cdn_fetcher.fetch_all", return_value={}):
            _, networks = load_cdn_networks(cache_file)

        assert len(networks) == 2
        assert str(networks[0]) == "104.16.0.0/13"
        assert str(networks[1]) == "151.101.0.0/16"
