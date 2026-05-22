"""IP resolution and tracking for CT Watcher."""

import json
import time
import ipaddress
from typing import List, Tuple

from .config import CDN_NETWORKS, ATTACKER_IPS_FILE
from .state import state
from .dns_resolver import resolve_a


def is_cdn_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to a known CDN/cloud provider."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in CDN_NETWORKS:
            if ip in network:
                return True
    except ValueError:
        pass
    return False


def resolve_domain_ip(domain: str) -> List[str]:
    """Resolve a domain to its IP address(es). Returns list of IPs."""
    return resolve_a(domain)


def save_attacker_ips(filepath: str = ATTACKER_IPS_FILE) -> None:
    """Save attacker IPs to JSON file."""
    try:
        with state.ip_save_lock:
            state.attacker_ips_data["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            with open(filepath, 'w') as f:
                json.dump(state.attacker_ips_data, f, indent=2)
    except Exception as e:
        print(f"[!] Error saving attacker IPs: {e}")


def track_attacker_ip(ip: str, domain: str, is_cdn: bool = False) -> None:
    """Track an attacker IP address with associated domain."""
    with state.ip_save_lock:
        ips_data = state.attacker_ips_data["ips"]

        if ip not in ips_data:
            ips_data[ip] = {
                "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "domains": [domain],
                "is_cdn": is_cdn,
                "count": 1
            }
            print(f"[+] New attacker IP tracked: {ip} {'(CDN)' if is_cdn else ''}")
        else:
            entry = ips_data[ip]
            entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            entry["count"] += 1
            if domain not in entry["domains"]:
                entry["domains"].append(domain)
                # Keep only last 50 domains per IP
                if len(entry["domains"]) > 50:
                    entry["domains"] = entry["domains"][-50:]

    # Save after each update (outside the lock to avoid reentrant acquisition)
    save_attacker_ips()


def get_attacker_ips_for_domain(domain: str) -> Tuple[List[str], List[str]]:
    """Resolve domain and track IPs.
    
    Returns tuple of (all_ips, non_cdn_ips).
    """
    all_ips = resolve_domain_ip(domain)
    non_cdn_ips = []
    
    for ip in all_ips:
        is_cdn = is_cdn_ip(ip)
        track_attacker_ip(ip, domain, is_cdn)
        if not is_cdn:
            non_cdn_ips.append(ip)
    
    return (all_ips, non_cdn_ips)


def resolve_and_classify(domain: str) -> Tuple[List[str], List[str]]:
    """Resolve domain IPs and classify CDN vs non-CDN. Does NOT track.

    Returns tuple of (all_ips, non_cdn_ips).
    """
    all_ips = resolve_domain_ip(domain)
    non_cdn_ips = [ip for ip in all_ips if not is_cdn_ip(ip)]
    return (all_ips, non_cdn_ips)


def track_resolved_ips(all_ips: List[str], non_cdn_ips: List[str], domain: str) -> None:
    """Track previously resolved IPs to attacker_ips.json."""
    non_cdn_set = set(non_cdn_ips)
    for ip in all_ips:
        track_attacker_ip(ip, domain, is_cdn=(ip not in non_cdn_set))
