"""Dynamic CDN IP range fetching and caching."""

import json
import os
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import requests

CACHE_FILE = "cdn_ranges_cache.json"
CACHE_TTL_SECONDS = 86400  # 24 hours

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
FASTLY_IP_URL = "https://api.fastly.com/public-ip-list"


def _fetch_cloudflare() -> List[str]:
    """Fetch Cloudflare IPv4 CIDR ranges."""
    resp = requests.get(CLOUDFLARE_IPV4_URL, timeout=10)
    resp.raise_for_status()
    cidrs = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if line and "/" in line:
            try:
                ipaddress.ip_network(line)
                cidrs.append(line)
            except ValueError:
                pass
    return cidrs


def _fetch_fastly() -> List[str]:
    """Fetch Fastly CIDR ranges from their API."""
    resp = requests.get(FASTLY_IP_URL, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cidrs = []
    for cidr in data.get("addresses", []):
        try:
            ipaddress.ip_network(cidr)
            cidrs.append(cidr)
        except ValueError:
            pass
    return cidrs


def fetch_all() -> Dict[str, List[str]]:
    """Fetch CDN ranges from all providers. Returns {provider: [cidrs]}."""
    results = {}

    try:
        results["cloudflare"] = _fetch_cloudflare()
    except Exception as e:
        print(f"[!] Failed to fetch Cloudflare CDN ranges: {e}")

    try:
        results["fastly"] = _fetch_fastly()
    except Exception as e:
        print(f"[!] Failed to fetch Fastly CDN ranges: {e}")

    return results


def save_cache(provider_ranges: Dict[str, List[str]], filepath: str = CACHE_FILE) -> None:
    """Save fetched CDN ranges to cache file."""
    cache = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "providers": provider_ranges,
    }
    with open(filepath, "w") as f:
        json.dump(cache, f, indent=2)


def load_cache(filepath: str = CACHE_FILE) -> Dict[str, List[str]] | None:
    """Load CDN ranges from cache if it exists and is not expired."""
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, "r") as f:
            cache = json.load(f)

        updated_at = datetime.fromisoformat(cache["updated_at"])
        age = (datetime.now(timezone.utc) - updated_at).total_seconds()
        if age > CACHE_TTL_SECONDS:
            print(
                f"[~] CDN cache is {age / 3600:.1f}h old"
                f" (>{CACHE_TTL_SECONDS / 3600:.0f}h), will refresh"
            )
            return None

        return cache.get("providers", {})
    except Exception as e:
        print(f"[!] Failed to load CDN cache: {e}")
        return None


def refresh_cdn_cache(filepath: str = CACHE_FILE) -> Dict[str, List[str]]:
    """Try to fetch fresh CDN ranges, falling back to cache on failure.

    Returns {provider: [cidrs]} dict.
    """
    fetched = fetch_all()
    if fetched:
        save_cache(fetched, filepath)
        return fetched

    cached = load_cache(filepath)
    if cached:
        print("[~] Using cached CDN ranges (fetch failed)")
        return cached

    print("[!] No CDN ranges available (fetch failed, no cache)")
    return {}


def load_cdn_networks(
    filepath: str = CACHE_FILE,
) -> Tuple[Dict[str, List[str]], List[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Load CDN ranges into ipaddress network objects for fast lookup.

    Tries to refresh cache first, then parses all CIDRs into networks.
    Returns (provider_ranges, networks_list).
    """
    provider_ranges = refresh_cdn_cache(filepath)
    networks = []
    for provider, cidrs in provider_ranges.items():
        for cidr in cidrs:
            try:
                networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass
    return provider_ranges, networks


def log_cdn_stats(provider_ranges: Dict[str, List[str]]) -> None:
    """Log how many CIDR ranges were loaded per provider."""
    total = 0
    for provider, cidrs in provider_ranges.items():
        count = len(cidrs)
        total += count
        print(f"[*] CDN ranges loaded: {provider} = {count} CIDRs")
    print(f"[*] CDN ranges total: {total} CIDRs")
