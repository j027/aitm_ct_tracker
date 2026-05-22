"""Domain checking functions - nameservers, registrar, attacker domain matching."""

from typing import Dict, List, Set, Tuple
import time
import whoisit

from .utils import get_base_domain
from .dns_resolver import resolve_ns


# RDAP bootstrap state and cache
_rdap_bootstrapped = False
_rdap_cache: Dict[str, tuple] = {}  # base_domain -> (registrar, reg_date, timestamp)
_RDAP_CACHE_TTL = 3600  # 1 hour


def _ensure_rdap_bootstrapped() -> bool:
    global _rdap_bootstrapped
    if not _rdap_bootstrapped:
        try:
            whoisit.bootstrap()
            _rdap_bootstrapped = True
        except Exception as e:
            print(f"[!] RDAP bootstrap failed: {e}")
            return False
    return _rdap_bootstrapped


def is_known_attacker_domain(domain: str, known_domains: Set[str]) -> bool:
    """Check if domain or its base domain matches known attacker domains."""
    domain = domain.lower().strip()
    
    if domain in known_domains:
        return True
    
    parts = domain.split('.')
    if len(parts) >= 2:
        for i in range(len(parts) - 1):
            base = '.'.join(parts[i:])
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
    base_domain = get_base_domain(domain)

    now = time.time()
    if base_domain in _rdap_cache:
        registrar, reg_date, cached_at = _rdap_cache[base_domain]
        if now - cached_at < _RDAP_CACHE_TTL:
            return (registrar, reg_date)

    registrar = None
    reg_date = None

    try:
        if _ensure_rdap_bootstrapped():
            result = whoisit.domain(base_domain)

            entities = result.get('entities', {})
            reg_entities = entities.get('registrar', [])
            if reg_entities and reg_entities[0].get('name'):
                registrar = reg_entities[0]['name']

            rd = result.get('registration_date')
            if rd:
                reg_date = rd.strftime('%Y-%m-%d') if hasattr(rd, 'strftime') else str(rd)[:10]
    except Exception as e:
        print(f"[~] RDAP lookup failed for {base_domain} ({e})")

    _rdap_cache[base_domain] = (registrar, reg_date, now)
    return (registrar, reg_date)
