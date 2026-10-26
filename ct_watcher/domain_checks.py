"""Domain checking functions - nameservers, registrar, attacker domain matching."""

from typing import Dict, List, Set, Tuple

from .utils import get_base_domain
from .dns_resolver import resolve_a, resolve_ns
from .models import DuoCheckResult
from .rdap import get_domain_info as _rdap_get_domain_info
from .console import log

DUO_INVALID_HOSTNAME = "api-invalid.duosecurity.com"


def check_duo_hostnames(api_ids: List[str]) -> Dict[str, DuoCheckResult]:
    """Check whether Duo API hostnames are provisioned or match the invalid wildcard.

    Resolves the invalid baseline once per call, then each
    ``api-<id>.duosecurity.com``. An ID is ``invalid`` when its A-record set
    matches the baseline exactly, ``valid`` when both resolve to different
    sets, and ``unknown`` when either lookup returns no A records.
    """
    if not api_ids:
        return {}

    unique_ids = list(dict.fromkeys(api_ids))
    invalid_ips = set(resolve_a(DUO_INVALID_HOSTNAME))
    if not invalid_ips:
        return {api_id: DuoCheckResult(status="unknown", a_records=[]) for api_id in unique_ids}

    results: Dict[str, DuoCheckResult] = {}
    for api_id in unique_ids:
        hostname = f"api-{api_id.strip().lower()}.duosecurity.com"
        a_records = resolve_a(hostname)
        if not a_records:
            status = "unknown"
        elif set(a_records) == invalid_ips:
            status = "invalid"
        else:
            status = "valid"
        results[api_id] = DuoCheckResult(status=status, a_records=a_records)
    return results


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
        log(f"[!] Error checking nameservers for {domain}: {e}")

    return (False, [])


def get_domain_info(domain: str) -> tuple:
    """Get registrar and registration date for a domain.

    Uses RDAP (structured JSON). Results are cached for 1 hour.

    Returns:
        (registrar, reg_date) where reg_date is 'YYYY-MM-DD' string or None.
    """
    return _rdap_get_domain_info(domain)
