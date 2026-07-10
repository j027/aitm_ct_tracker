"""File loading functions for CT Watcher."""

import json
import os
import ipaddress
from typing import Dict, Set, Any

from .config import (
    KNOWN_DOMAINS_FILE,
    EXPIRED_DOMAINS_FILE,
    TARGETS_FILE,
    EMAIL_TEMPLATE_FILE,
    ATTACKER_IPS_FILE,
    KNOWN_IPS_FILE,
    WATCHED_ORG_IDS_FILE,
)

DEFAULT_EMAIL_TEMPLATE = """To the Security Team,

I detected new SSL certificate registrations matching known AitM
phishing patterns that appear to be targeting your organization.

{IDENTIFIER}

IOCs:
{IOCS_LIST}

Context: Likely staging for a credential harvesting campaign. Recommended block on network edge.

Regards"""


def load_known_attacker_domains(filepath: str = KNOWN_DOMAINS_FILE) -> Set[str]:
    """Load known attacker domains from file and un-defang them.

    Expected format: one domain per line, defanged like littlenuggetsco[.]com
    """
    domains = set()
    if not os.path.exists(filepath):
        print(f"[*] No known domains file found at {filepath}")
        return domains

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Un-defang: replace [.] with .
                domain = line.replace("[.]", ".").replace("[dot]", ".").lower()
                domains.add(domain)
        print(f"[*] Loaded {len(domains)} known attacker domains")
    except Exception as e:
        print(f"[!] Error loading known domains: {e}")

    return domains


def load_expired_domains(filepath: str = EXPIRED_DOMAINS_FILE) -> Set[str]:
    """Load expired domains from file and un-defang them.

    Expected format: one domain per line, defanged like littlenuggetsco[.]com
    Returns empty set if file doesn't exist (no expired domains known yet).
    """
    domains = set()
    if not os.path.exists(filepath):
        print(f"[*] No expired domains file found at {filepath} — starting fresh")
        return domains

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domain = line.replace("[.]", ".").replace("[dot]", ".").lower()
                domains.add(domain)
        print(f"[*] Loaded {len(domains)} expired domains")
    except Exception as e:
        print(f"[!] Error loading expired domains: {e}")

    return domains


def load_target_mapping(
    filepath: str = TARGETS_FILE,
) -> tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, Any]]]:
    """Load target organization mapping from JSON file.

    Returns (duo_targets, keyword_targets).  Entries without ``"type":
    "keyword"`` are treated as Duo targets (backwards compatible).  Entries
    with ``"type": "keyword"`` are keyword-based targets suitable for
    organizations that may not use Duo, or may only use it for some users.

    Duo format::

        {"hex_id": {"name": "Org Name", "email": "email@example.com"}}

    Keyword format::

        {"keyword_id": {"type": "keyword", "name": "Org Name",
         "email": "email@example.com", "keywords": ["word1", "word2"]}}
    """
    duo_targets: Dict[str, Dict[str, str]] = {}
    keyword_targets: Dict[str, Dict[str, Any]] = {}

    if not os.path.exists(filepath):
        print(f"[*] No targets file found at {filepath}")
        return duo_targets, keyword_targets

    try:
        with open(filepath, "r") as f:
            mapping: Dict[str, Dict[str, Any]] = json.load(f)

        duo_count = 0
        kw_count = 0
        for key, value in mapping.items():
            if value.get("type") == "keyword":
                keyword_targets[key] = value
                kw_count += 1
            else:
                duo_targets[key] = {k: v for k, v in value.items() if k != "type"}
                duo_count += 1

        print(f"[*] Loaded {duo_count} Duo + {kw_count} keyword targets ({len(mapping)} total)")
    except Exception as e:
        print(f"[!] Error loading targets: {e}")

    return duo_targets, keyword_targets


def load_email_template(filepath: str = EMAIL_TEMPLATE_FILE) -> str:
    """Load email body template from file. Returns default template if file not found."""
    if not os.path.exists(filepath):
        print(f"[*] No email template found at {filepath}, using default")
        return DEFAULT_EMAIL_TEMPLATE

    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        print(f"[!] Error loading email template: {e}, using default")
        return DEFAULT_EMAIL_TEMPLATE


def load_attacker_ips(filepath: str = ATTACKER_IPS_FILE) -> Dict[str, Any]:
    """Load attacker IPs from JSON file."""
    default_structure = {"ips": {}, "last_updated": None}

    if not os.path.exists(filepath):
        return default_structure

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        # Ensure the expected structure exists
        if "ips" not in data:
            data["ips"] = {}
        if "last_updated" not in data:
            data["last_updated"] = None
        print(f"[*] Loaded {len(data.get('ips', {}))} tracked attacker IPs")
        return data
    except Exception as e:
        print(f"[!] Error loading attacker IPs: {e}")
        return default_structure


def load_known_attacker_ips(filepath: str = KNOWN_IPS_FILE) -> Set[str]:
    """Load manually curated confirmed attacker IPs from file.

    Expected format: one IP per line, comments allowed with '#'.
    """
    known_ips: Set[str] = set()
    if not os.path.exists(filepath):
        print(f"[*] No known attacker IP file found at {filepath}")
        return known_ips

    invalid_count = 0
    try:
        with open(filepath, "r") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    ip = ipaddress.ip_address(line)
                    known_ips.add(str(ip))
                except ValueError:
                    invalid_count += 1

        print(f"[*] Loaded {len(known_ips)} confirmed attacker IPs")
        if invalid_count:
            print(f"[~] Skipped {invalid_count} invalid IP entries in {filepath}")
    except Exception as e:
        print(f"[!] Error loading known attacker IPs: {e}")

    return known_ips


def load_watched_org_ids(filepath: str = WATCHED_ORG_IDS_FILE) -> Set[str]:
    """Load watched organization IDs from file.

    Expected format: one target ID per line (same keys as targets.json).
    Lines starting with '#' and blank lines are ignored.
    """
    watched: Set[str] = set()
    if not os.path.exists(filepath):
        return watched

    try:
        with open(filepath, "r") as f:
            for raw_line in f:
                line = raw_line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                watched.add(line)
        if watched:
            print(f"[*] Loaded {len(watched)} watched org IDs")
    except Exception as e:
        print(f"[!] Error loading watched org IDs: {e}")

    return watched
