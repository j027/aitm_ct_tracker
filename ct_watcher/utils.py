"""Utility functions for CT Watcher."""

import re
import time
from typing import Dict, List

from publicsuffixlist import PublicSuffixList

from .config import COMMON_WORDS_5CHAR, COMMON_WORDS_8CHAR, DOMAIN_REGEX


def defang_domain(domain: str) -> str:
    """Defang a domain by replacing dots with [.]"""
    return domain.replace(".", "[.]")


def extract_target_id(domain: str) -> str | None:
    """Extract the ID from a domain matching our pattern.

    Returns the ID (5-8 char alphanumeric) or None if not found.
    """
    match = re.match(r"^api-([0-9a-zA-Z]{5,8})[\.\-]", domain, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def is_common_word_id(api_id: str | None) -> bool:
    """Check if the API ID is a common English word (false positive).

    Returns True if the ID appears to be a common word and should be filtered.
    Returns False if:
      - The ID contains digits (intentional obfuscation like 'admin1')
      - The ID is not in our common words list
    """
    if not api_id:
        return False

    api_id_lower = api_id.lower()

    # If it contains any digits, it's likely intentional (e.g., 'adm1n', '3dse1')
    # These should NOT be filtered - they look like target IDs
    if any(c.isdigit() for c in api_id_lower):
        return False

    # Check against our word lists based on length
    if len(api_id_lower) == 5:
        return api_id_lower in COMMON_WORDS_5CHAR
    elif len(api_id_lower) == 8:
        return api_id_lower in COMMON_WORDS_8CHAR

    return False


def extract_all_target_ids(all_domains: List[str]) -> Dict[str, str]:
    """Extract all unique Duo api-IDs from a certificate's domain list.

    Scans every domain for an ``api-<ID>.`` pattern, filters out common-word
    false positives, and returns a dict mapping each unique api-ID to the
    first domain it was found on.

    Returns:
        ``{api_id: first_matching_domain}``, empty dict if none found.
    """
    results: Dict[str, str] = {}
    for d in all_domains:
        domain = d.strip().lower()
        if not DOMAIN_REGEX.match(domain):
            continue
        api_id = extract_target_id(domain)
        if not api_id or is_common_word_id(api_id):
            continue
        if api_id not in results:
            results[api_id] = domain
    return results


def ids_for_target(
    api_ids: List[str],
    target_email: str | None,
    target_mapping: Dict[str, Dict[str, str]],
) -> List[str]:
    """Get the api-IDs belonging to the given target (matched by email).

    If ``target_email`` is falsy, returns the first ID (or empty list).
    """
    if not target_email:
        return api_ids[:1] if api_ids else []
    return [a for a in api_ids if target_mapping.get(a, {}).get("email") == target_email]


def match_keyword_targets(
    all_domains: List[str],
    keyword_targets: Dict[str, Dict],
) -> Dict[str, list]:
    """Scan certificate domains for keyword-target matches.

    For each domain split by ``.``, each subdomain part is checked for
    each keyword (case-insensitive substring match).

    Returns:
        ``{keyword_id: [matching_domain, ...]}`` for targets with at
        least one matching domain.
    """
    results: Dict[str, list] = {}

    for domain in all_domains:
        d = domain.strip().lower()
        parts = d.split(".")
        for kw_id, target in keyword_targets.items():
            keywords = target.get("keywords", [kw_id])
            if any(kw.lower() in part for part in parts for kw in keywords):
                results.setdefault(kw_id, []).append(d)

    return results


_DUO_ATTRIBUTION_NOTE = (
    "Note: I attributed this Duo API hostname to your organization via OSINT"
    " research and it may not be 100% reliable. If you believe this reached"
    " the wrong organization, please let me know. It helps me improve"
    " accuracy."
)

_KEYWORD_ATTRIBUTION_NOTE = (
    "Note: This detection is based on a distinctive keyword match. The"
    " target organization may not use Duo, or may only use it for some"
    " users. If you believe this is a false positive or reached the wrong"
    " organization, please let me know."
)


def build_identifier_text(api_ids: List[str] | None = None, keyword: str | None = None) -> str:
    """Build the identifier block for email templates.

    Returns the full ``{IDENTIFIER}`` replacement text — label, value, and
    attribution note — appropriate for the target type.
    """
    if keyword:
        return f"Keyword match: {keyword}\n\n{_KEYWORD_ATTRIBUTION_NOTE}"
    if api_ids:
        duo_urls = [f"https://api-{aid}.duosecurity.com" for aid in api_ids]
        duo_str = "\n".join(duo_urls)
        return f"Duo API hostname:\n{duo_str}\n\n{_DUO_ATTRIBUTION_NOTE}"
    return ""


def format_duo_ids(
    api_ids: List[str],
    target_mapping: Dict[str, Dict[str, str]],
) -> tuple[str, str | None]:
    """Format Duo IDs and target names for display.

    Returns a ``(duo_ids_str, targets_str_or_None)`` tuple.
    For a single ID, returns ``("``abc``", None)`` — no paired targets needed.
    For multiple IDs, returns the comma-separated IDs and matching targets.
    """
    if len(api_ids) <= 1:
        return f"`{api_ids[0]}`" if api_ids else "", None
    duo_parts = [f"`{aid}`" for aid in api_ids]
    target_parts = []
    for aid in api_ids:
        ti = target_mapping.get(aid)
        target_parts.append(ti["name"] if ti else "(unknown)")
    return ", ".join(duo_parts), ", ".join(target_parts)


_psl = PublicSuffixList(only_icann=True)


def get_base_domain(domain: str) -> str:
    """Extract the registrable domain using the Public Suffix List."""
    suffix = _psl.privatesuffix(domain)
    if suffix is not None:
        return suffix
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def calculate_freshness(cert_timestamp: float | None, fmt: str = "discord") -> str:
    """Calculate certificate freshness string.

    Args:
        cert_timestamp: Unix timestamp of certificate not_before, or None.
        fmt: Output format — "discord" for <t:unix:R>, "plain" for human-readable text.

    Returns:
        Formatted freshness string, or "Unknown" if timestamp is None.
    """
    if cert_timestamp is None:
        return "Unknown"

    if fmt == "discord":
        return f"<t:{int(cert_timestamp)}:R>"

    age_seconds = int(max(0, time.time() - cert_timestamp))
    if age_seconds < 60:
        return f"{age_seconds} seconds"
    if age_seconds < 3600:
        return f"{age_seconds // 60} minutes"
    return f"{age_seconds // 3600} hours"
