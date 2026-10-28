"""File loading functions for CT Watcher."""

import json
import os
import ipaddress
import re
from typing import Dict, List, Optional, Set, Any

from .config import (
    KNOWN_DOMAINS_FILE,
    TARGETS_FILE,
    EMAIL_TEMPLATE_FILE,
    ATTACKER_IPS_FILE,
    KNOWN_IPS_FILE,
    WATCHED_ORG_IDS_FILE,
    NOISE_WORDS_FILE,
)
from .console import log
from .models import NoiseDictionary

DEFAULT_EMAIL_TEMPLATE = """To the Security Team,

I detected new SSL certificate registrations matching known AitM
phishing patterns that appear to be targeting your organization.

{IDENTIFIER}

IOCs:
{IOCS_LIST}

Context: Likely staging for a credential harvesting campaign. Recommended block on network edge.

Regards"""

_EXACT_NOISE_WORD_RE = re.compile(r"^[0-9a-z]{5,8}$")
_NOISE_PATTERN_RE = re.compile(r"^[a-z]{1,7}#$")


def load_noise_words(filepath: str = NOISE_WORDS_FILE) -> NoiseDictionary:
    """Load the api-<id> false-positive dictionary.

    Expected format: one exact word (5-8 characters) per line, or ``word#``
    to match one or more trailing digits. Blank lines and lines starting
    with ``#`` are ignored. Missing or malformed files raise so a typo
    cannot silently disable noise filtering.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Noise dictionary not found: {filepath}")

    words: Set[str] = set()
    patterns: List[re.Pattern] = []
    seen: Set[str] = set()

    with open(filepath, "r") as f:
        for line_number, raw_line in enumerate(f, start=1):
            entry = raw_line.strip().lower()
            if not entry or entry.startswith("#"):
                continue
            if entry in seen:
                raise ValueError(f"{filepath}:{line_number}: duplicate entry {entry!r}")
            seen.add(entry)

            if entry.endswith("#"):
                if not _NOISE_PATTERN_RE.fullmatch(entry):
                    raise ValueError(
                        f"{filepath}:{line_number}: invalid pattern {entry!r}; "
                        "expected 1-7 lowercase letters followed by '#'"
                    )
                base = entry[:-1]
                patterns.append(re.compile(rf"^{re.escape(base)}\d+$"))
            else:
                if not _EXACT_NOISE_WORD_RE.fullmatch(entry):
                    raise ValueError(
                        f"{filepath}:{line_number}: invalid word {entry!r}; "
                        "expected 5-8 lowercase letters/digits"
                    )
                words.add(entry)

    if not words and not patterns:
        raise ValueError(f"Noise dictionary is empty: {filepath}")

    log(f"[*] Loaded {len(words)} noise words and {len(patterns)} digit patterns")
    return NoiseDictionary(frozenset(words), tuple(patterns))


def load_known_attacker_domains(filepath: str = KNOWN_DOMAINS_FILE) -> Set[str]:
    """Load known attacker domains from file and un-defang them.

    Expected format: one domain per line, defanged like littlenuggetsco[.]com
    """
    domains = set()
    if not os.path.exists(filepath):
        log(f"[*] No known domains file found at {filepath}")
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
        log(f"[*] Loaded {len(domains)} known attacker domains")
    except Exception as e:
        log(f"[!] Error loading known domains: {e}")

    return domains


def _normalize_exclude_domains(target_key: str, value: Dict[str, Any]) -> List[str]:
    """Validate and normalize a target's ``exclude_domains`` suffix list."""
    if "exclude_domains" not in value:
        return []

    raw = value["exclude_domains"]
    if not isinstance(raw, list):
        raise ValueError(f"{target_key}: exclude_domains must be a list")

    normalized: List[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ValueError(f"{target_key}: exclude_domains entries must be strings")

        domain = entry.strip().lower().rstrip(".")
        if not domain:
            raise ValueError(f"{target_key}: exclude_domains contains an empty entry")
        if domain.startswith(".") or "*" in domain or "/" in domain or ":" in domain:
            raise ValueError(f"{target_key}: invalid exclude_domains entry {entry!r}")
        if any(c.isspace() for c in domain):
            raise ValueError(f"{target_key}: invalid exclude_domains entry {entry!r}")
        if domain not in normalized:
            normalized.append(domain)

    return normalized


def _validate_keywords(target_key: str, value: Dict[str, Any]) -> Optional[List[str]]:
    """Validate ``keywords`` when present. Returns None when omitted."""
    if "keywords" not in value:
        return None

    keywords = value["keywords"]
    if not isinstance(keywords, list) or not keywords:
        raise ValueError(f"{target_key}: keywords must be a non-empty list")
    if any(not isinstance(k, str) or not k.strip() for k in keywords):
        raise ValueError(f"{target_key}: keywords entries must be non-empty strings")

    return [k.strip() for k in keywords]


def load_target_mapping(
    filepath: str = TARGETS_FILE,
) -> tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, Any]]]:
    """Load target organization mapping from JSON file.

    Returns (duo_targets, keyword_targets).  Entries without ``"type":
    "keyword"`` are treated as Duo targets (backwards compatible).  Entries
    with ``"type": "keyword"`` are keyword-based targets suitable for
    organizations that may not use Duo, or may only use it for some users.

    Duo format::

        {"hex_id": {"name": "Org Name", "email": "email@example.com",
         "keywords": ["word1"], "exclude_domains": ["example.edu"]}}

    Keyword format::

        {"keyword_id": {"type": "keyword", "name": "Org Name",
         "email": "email@example.com", "keywords": ["word1", "word2"],
         "exclude_domains": ["example.edu"]}}

    ``exclude_domains`` is only valid for targets with keywords. It lists
    domain suffixes whose keyword matches should be ignored.
    """
    duo_targets: Dict[str, Dict[str, str]] = {}
    keyword_targets: Dict[str, Dict[str, Any]] = {}

    if not os.path.exists(filepath):
        log(f"[*] No targets file found at {filepath}")
        return duo_targets, keyword_targets

    try:
        with open(filepath, "r") as f:
            mapping: Dict[str, Dict[str, Any]] = json.load(f)
    except Exception as e:
        log(f"[!] Error loading targets: {e}")
        return duo_targets, keyword_targets

    if not isinstance(mapping, dict):
        raise ValueError(f"{filepath}: targets file must contain a JSON object")

    duo_count = 0
    kw_count = 0
    for key, value in mapping.items():
        if not isinstance(value, dict):
            raise ValueError(f"{key}: target entry must be an object")

        excludes = _normalize_exclude_domains(key, value)
        keywords = _validate_keywords(key, value)

        if value.get("type") == "keyword":
            if keywords is not None:
                value["keywords"] = keywords
            value["exclude_domains"] = excludes
            keyword_targets[key] = value
            kw_count += 1
            continue

        duo_targets[key] = {k: v for k, v in value.items() if k != "type"}
        duo_count += 1

        if keywords:
            kw_key = keywords[0]
            if kw_key not in keyword_targets:
                keyword_targets[kw_key] = {
                    "type": "keyword",
                    "name": value["name"],
                    "email": value.get("email", ""),
                    "keywords": keywords,
                    "exclude_domains": excludes,
                }
        elif excludes:
            raise ValueError(f"{key}: exclude_domains requires keywords")

    log(f"[*] Loaded {duo_count} Duo + {kw_count} keyword targets ({len(mapping)} total)")

    return duo_targets, keyword_targets


def load_email_template(filepath: str = EMAIL_TEMPLATE_FILE) -> str:
    """Load email body template from file. Returns default template if file not found."""
    if not os.path.exists(filepath):
        log(f"[*] No email template found at {filepath}, using default")
        return DEFAULT_EMAIL_TEMPLATE

    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        log(f"[!] Error loading email template: {e}, using default")
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
        log(f"[*] Loaded {len(data.get('ips', {}))} tracked attacker IPs")
        return data
    except Exception as e:
        log(f"[!] Error loading attacker IPs: {e}")
        return default_structure


def load_known_attacker_ips(filepath: str = KNOWN_IPS_FILE) -> Set[str]:
    """Load manually curated confirmed attacker IPs from file.

    Expected format: one IP per line, comments allowed with '#'.
    """
    known_ips: Set[str] = set()
    if not os.path.exists(filepath):
        log(f"[*] No known attacker IP file found at {filepath}")
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

        log(f"[*] Loaded {len(known_ips)} confirmed attacker IPs")
        if invalid_count:
            log(f"[~] Skipped {invalid_count} invalid IP entries in {filepath}")
    except Exception as e:
        log(f"[!] Error loading known attacker IPs: {e}")

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
            log(f"[*] Loaded {len(watched)} watched org IDs")
    except Exception as e:
        log(f"[!] Error loading watched org IDs: {e}")

    return watched
