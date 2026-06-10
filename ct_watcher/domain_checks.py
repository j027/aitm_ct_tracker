"""Domain checking functions - nameservers, registrar, attacker domain matching."""

from typing import List, Set, Tuple

from .utils import get_base_domain
from .dns_resolver import resolve_ns
from .rdap import get_domain_info as _rdap_get_domain_info


def is_known_attacker_domain(domain: str, known_domains: Set[str]) -> bool:
    """Check if domain or its base domain matches known attacker domains."""
    domain = domain.lower().strip()

    if domain in known_domains:
        return True

    parts = domain.split(".")
    if len(parts) >= 2:
        for i in range(len(parts) - 1):
            base = ".".join(parts[i:])
            if base in known_domains:
                return True

    return False


def get_nameservers(domain: str) -> Tuple[bool, List[str]]:
    """Get nameservers for a domain.

    Returns tuple of (is_cloudflare, nameservers_list).
    """
    try:
        base_domain = get_base_domain(domain)

        nameservers_list = resolve_ns(base_domain)

        if not nameservers_list:
            return (False, [])

        is_cloudflare = any(
            "cloudflare" in ns.lower() or "ns.cloudflare.com" in ns.lower()
            for ns in nameservers_list
        )

        return (is_cloudflare, nameservers_list)
    except Exception as e:
        print(f"[!] Error checking nameservers for {domain}: {e}")

    return (False, [])


def get_domain_info(domain: str) -> tuple:
    """Get registrar and registration date for a domain.

    Uses RDAP (structured JSON). Results are cached for 1 hour.

    Returns:
        (registrar, reg_date) where reg_date is 'YYYY-MM-DD' string or None.
    """
    return _rdap_get_domain_info(domain)
