"""Utility functions for CT Watcher."""

from __future__ import annotations

import re
import time
from typing import Dict, List

from publicsuffixlist import PublicSuffixList

from .config import DOMAIN_REGEX
from .models import DuoCheckResult, NoiseDictionary


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


def is_common_word_id(api_id: str | None, noise: NoiseDictionary) -> bool:
    """Return True if the API ID is a known common-word false positive.

    Exact dictionary entries are checked first, then explicit ``word#``
    digit patterns. IDs containing digits that are not explicitly listed
    are left alone because attackers mangle real Duo IDs.
    """
    if not api_id:
        return False

    candidate = api_id.lower()
    if candidate in noise.words:
        return True
    return any(pattern.fullmatch(candidate) for pattern in noise.patterns)


def extract_all_target_ids(all_domains: List[str], noise: NoiseDictionary) -> Dict[str, str]:
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
        if not api_id or is_common_word_id(api_id, noise):
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


def is_domain_excluded(domain: str, exclude_domains: List[str]) -> bool:
    """Return True if domain equals or is a subdomain of an excluded suffix.

    ``example.edu`` matches ``example.edu`` and ``*.example.edu`` but not
    ``notexample.edu`` or ``example.edu.evil.com``.
    """
    d = domain.strip().lower().rstrip(".")
    for suffix in exclude_domains:
        s = suffix.strip().lower().rstrip(".")
        if d == s or d.endswith("." + s):
            return True
    return False


def match_keyword_targets(
    all_domains: List[str],
    keyword_targets: Dict[str, Dict],
) -> Dict[str, list]:
    """Scan certificate domains for keyword-target matches.

    For each domain split by ``.``, each subdomain part is checked for
    each keyword (case-insensitive substring match). Domains matching a
    target's ``exclude_domains`` suffix list are skipped.

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
            if not _matching_keywords_in_parts(parts, keywords):
                continue
            if is_domain_excluded(d, target.get("exclude_domains", [])):
                continue
            results.setdefault(kw_id, []).append(d)

    return results


def _matching_keywords_in_parts(parts: List[str], keywords: List[str]) -> List[str]:
    """Return configured keywords matching any of the domain parts."""
    return [kw for kw in keywords if any(kw.lower() in part for part in parts)]


def find_matching_keywords(all_domains: List[str], keywords: List[str]) -> List[str]:
    """Return unique configured keywords matching any supplied domain."""
    matches: List[str] = []
    seen: set[str] = set()

    for domain in all_domains:
        parts = domain.strip().lower().split(".")
        for keyword in _matching_keywords_in_parts(parts, keywords):
            normalized = keyword.lower()
            if normalized not in seen:
                seen.add(normalized)
                matches.append(keyword)

    return matches


_DUO_ATTRIBUTION_NOTE = (
    "Note: I associated this Duo API hostname with your organization via"
    " OSINT and it may not be 100% reliable. If you believe this reached"
    " the wrong organization, please let me know. It helps me improve"
    " accuracy."
)

_KEYWORD_ATTRIBUTION_NOTE = (
    "Note: This alert is based on a keyword match,"
    " which is more likely to result in false positives."
    " If you believe this is a false positive or reached the"
    " wrong organization, please let me know."
)


def build_identifier_text(
    api_ids: List[str] | None = None,
    keyword: str | None = None,
    matched_keywords: List[str] | None = None,
) -> str:
    """Build the identifier block for email templates.

    Returns the full ``{IDENTIFIER}`` replacement text — label, value, and
    attribution note — appropriate for the target type.
    """
    if keyword:
        if not matched_keywords:
            raise ValueError("matched_keywords is required for keyword alerts")
        keyword_text = ", ".join(matched_keywords)
        return f"Matched keyword(s): {keyword_text}\n\n{_KEYWORD_ATTRIBUTION_NOTE}"
    if api_ids:
        duo_urls = [f"https://api-{aid}.duosecurity.com" for aid in api_ids]
        duo_str = "\n".join(duo_urls)
        return f"Duo API hostname:\n{duo_str}\n\n{_DUO_ATTRIBUTION_NOTE}"
    return ""


_DUO_STATUS_LABELS = {
    "valid": "✅ valid Duo",
    "invalid": "❌ invalid Duo",
    "unknown": "❔ unknown",
}


def _format_duo_id(api_id: str, duo_checks: Dict[str, DuoCheckResult] | None) -> str:
    """Format one Duo ID with its advisory status when available."""
    text = f"`{api_id}`"
    if duo_checks:
        check = duo_checks.get(api_id)
        if check:
            text += f" — {_DUO_STATUS_LABELS.get(check.status, check.status)}"
    return text


def format_duo_ids(
    api_ids: List[str],
    target_mapping: Dict[str, Dict[str, str]],
    duo_checks: Dict[str, DuoCheckResult] | None = None,
) -> tuple[str, str | None]:
    """Format Duo IDs and target names for display.

    Returns a ``(duo_ids_str, targets_str_or_None)`` tuple.
    For a single ID, returns ``("``abc``", None)`` — no paired targets needed.
    For multiple IDs, returns the comma-separated IDs and matching targets.
    ``duo_checks`` adds the advisory valid/invalid/unknown status.
    """
    if len(api_ids) <= 1:
        return _format_duo_id(api_ids[0], duo_checks) if api_ids else "", None
    duo_parts = [_format_duo_id(aid, duo_checks) for aid in api_ids]
    target_parts = []
    for aid in api_ids:
        ti = target_mapping.get(aid)
        target_parts.append(ti["name"] if ti else "(unknown)")
    return ", ".join(duo_parts), ", ".join(target_parts)


_DUO_CHECK_DETAIL_LIMIT = 10


def format_duo_check_lines(
    api_ids: List[str],
    duo_checks: Dict[str, DuoCheckResult] | None,
) -> str | None:
    """Build the advisory detail block for invalid/unknown Duo hostnames."""
    if not duo_checks:
        return None

    lines: List[str] = []
    invalid_count = 0
    for aid in api_ids:
        check = duo_checks.get(aid)
        if not check:
            continue
        hostname = f"api-{aid}.duosecurity.com"
        if check.status == "invalid":
            records = ", ".join(check.a_records) if check.a_records else "no A record"
            lines.append(f"❌ `{hostname}` → `{records}`")
            invalid_count += 1
        elif check.status == "unknown":
            lines.append(f"❔ `{hostname}` — DNS lookup failed")

    if not lines:
        return None
    if len(lines) > _DUO_CHECK_DETAIL_LIMIT:
        omitted = len(lines) - _DUO_CHECK_DETAIL_LIMIT
        lines = lines[:_DUO_CHECK_DETAIL_LIMIT]
        lines.append(f"... and {omitted} more")
    if invalid_count:
        lines.append("")
        lines.append("Matches the known-invalid wildcard `api-invalid.duosecurity.com`.")
    return "\n".join(lines)


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


def is_base_domain_only_cert(all_domains: List[str]) -> bool:
    """Return True when every SAN is only its registrable base domain.

    A SAN qualifies when, after dropping one leading ``*.`` and one leading
    ``www.``, it equals its own registrable base domain. This is the shape of
    certificates auto-issued by CDNs and registrars/registrar parking
    (Cloudflare Universal SSL, GoDaddy/Afternic/Hostinger parking certs,
    registrar bulk-parking certs). Such certificates never carry
    target-specific subdomains and are pure noise for phishing detection.

    Returns False as soon as any SAN contains a real subdomain
    (e.g. ``api-12345678.example.com`` or ``blog.example.com``).
    """
    hosts: List[str] = []
    for raw in all_domains:
        host = raw.strip().lower()
        if host.startswith("*."):
            host = host[2:]
        if host.startswith("www."):
            host = host[4:]
        if not host:
            return False
        hosts.append(host)
    return bool(hosts) and all(host == get_base_domain(host) for host in hosts)


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
